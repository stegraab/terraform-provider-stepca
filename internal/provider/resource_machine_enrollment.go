package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = &machineEnrollmentResource{}
	_ resource.ResourceWithConfigure = &machineEnrollmentResource{}
)

type machineEnrollmentResource struct {
	client *stepAPIClient
}

type machineEnrollmentResourceModel struct {
	ID               types.String `tfsdk:"id"`
	AttestorType     types.String `tfsdk:"attestor_type"`
	AttestorIdentity types.String `tfsdk:"attestor_identity"`
	AttestorClaims   types.Map    `tfsdk:"attestor_claims"`
	MachineIdentity  types.String `tfsdk:"machine_identity"`
	SSHPrincipals    types.Set    `tfsdk:"ssh_principals"`
	Status           types.String `tfsdk:"status"`
}

func NewMachineEnrollmentResource() resource.Resource {
	return &machineEnrollmentResource{}
}

func (r *machineEnrollmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_machine_enrollment"
}

func (r *machineEnrollmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Attributes: map[string]schema.Attribute{
		"id": schema.StringAttribute{Computed: true},
		"attestor_type": schema.StringAttribute{
			Required:      true,
			Description:   "Platform attestor type, for example nutanix-vtpm.",
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"attestor_identity": schema.StringAttribute{
			Required:      true,
			Description:   "Stable inventory identity within the attestor type, for example a Nutanix VM external ID.",
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"attestor_claims": schema.MapAttribute{
			Required:      true,
			ElementType:   types.StringType,
			Description:   "Expected platform claims verified during attestation, such as generation_uuid and vtpm_disk_id.",
			PlanModifiers: []planmodifier.Map{mapplanmodifier.RequiresReplace()},
		},
		"machine_identity": schema.StringAttribute{
			Required:      true,
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"ssh_principals": schema.SetAttribute{
			Required:      true,
			ElementType:   types.StringType,
			PlanModifiers: []planmodifier.Set{setplanmodifier.RequiresReplace()},
		},
		"status": schema.StringAttribute{Computed: true},
	}}
}

func (r *machineEnrollmentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*stepAPIClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type", fmt.Sprintf("Expected *stepAPIClient, got: %T", req.ProviderData))
		return
	}
	r.client = client
}

func (r *machineEnrollmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan machineEnrollmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	input, ok := expandMachineEnrollment(ctx, plan, resp)
	if !ok {
		return
	}
	created, err := r.client.createMachineEnrollment(ctx, input)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create machine enrollment", err.Error())
		return
	}
	resp.Diagnostics.Append(setMachineEnrollmentState(ctx, &plan, created)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *machineEnrollmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state machineEnrollmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	registration, found, err := r.client.getMachineEnrollment(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read machine enrollment", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	if isInactiveMachineEnrollmentStatus(registration.Status) {
		resp.Diagnostics.AddError(
			"Machine enrollment is inactive",
			fmt.Sprintf("Registration %s has status %q. Review why it became inactive, then explicitly replace this resource.", registration.ID, registration.Status),
		)
		return
	}
	resp.Diagnostics.Append(setMachineEnrollmentState(ctx, &state, registration)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func isInactiveMachineEnrollmentStatus(status string) bool {
	return status == "expired" || status == "revoked"
}

func (r *machineEnrollmentResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Machine enrollment update is unsupported", "All configurable attributes require replacement.")
}

func (r *machineEnrollmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state machineEnrollmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.revokeMachineEnrollment(ctx, state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to revoke machine enrollment", err.Error())
	}
}

func expandMachineEnrollment(ctx context.Context, plan machineEnrollmentResourceModel, resp *resource.CreateResponse) (machineEnrollment, bool) {
	claims := make(map[string]string)
	resp.Diagnostics.Append(plan.AttestorClaims.ElementsAs(ctx, &claims, false)...)
	principals := make([]string, 0)
	resp.Diagnostics.Append(plan.SSHPrincipals.ElementsAs(ctx, &principals, false)...)
	if resp.Diagnostics.HasError() {
		return machineEnrollment{}, false
	}
	return machineEnrollment{
		AttestorType: plan.AttestorType.ValueString(), AttestorIdentity: plan.AttestorIdentity.ValueString(),
		AttestorClaims: claims, MachineIdentity: plan.MachineIdentity.ValueString(), SSHPrincipals: principals,
	}, true
}

func setMachineEnrollmentState(ctx context.Context, state *machineEnrollmentResourceModel, registration machineEnrollment) []diag.Diagnostic {
	var diagnostics diag.Diagnostics
	state.ID = types.StringValue(registration.ID)
	state.AttestorType = types.StringValue(registration.AttestorType)
	state.AttestorIdentity = types.StringValue(registration.AttestorIdentity)
	state.MachineIdentity = types.StringValue(registration.MachineIdentity)
	state.Status = types.StringValue(registration.Status)
	claims, claimDiagnostics := types.MapValueFrom(ctx, types.StringType, registration.AttestorClaims)
	diagnostics.Append(claimDiagnostics...)
	state.AttestorClaims = claims
	principals, principalDiagnostics := types.SetValueFrom(ctx, types.StringType, registration.SSHPrincipals)
	diagnostics.Append(principalDiagnostics...)
	state.SSHPrincipals = principals
	return diagnostics
}
