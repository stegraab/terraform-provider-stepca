package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = &certificateResource{}
	_ resource.ResourceWithConfigure = &certificateResource{}
)

type certificateResource struct {
	client *stepAPIClient
}

type certificateResourceModel struct {
	ID                         types.String `tfsdk:"id"`
	CommonName                 types.String `tfsdk:"common_name"`
	ProvisionerName            types.String `tfsdk:"provisioner_name"`
	ProvisionerPassword        types.String `tfsdk:"provisioner_password_wo"`
	ProvisionerPasswordVersion types.String `tfsdk:"provisioner_password_version"`
	SANs                       types.Set    `tfsdk:"sans"`
	NotAfter                   types.String `tfsdk:"not_after"`
	RenewalVersion             types.String `tfsdk:"renewal_version"`
	CertificatePEM             types.String `tfsdk:"certificate_pem"`
	CertificateChainPEM        types.String `tfsdk:"certificate_chain_pem"`
	CAPEM                      types.String `tfsdk:"ca_pem"`
	PrivateKeyPEM              types.String `tfsdk:"private_key_pem"`
	SerialNumber               types.String `tfsdk:"serial_number"`
	NotBefore                  types.String `tfsdk:"not_before"`
	ExpiresAt                  types.String `tfsdk:"expires_at"`
}

func NewCertificateResource() resource.Resource {
	return &certificateResource{}
}

func (r *certificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (r *certificateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"common_name": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Certificate subject common name.",
			},
			"provisioner_name": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "JWK provisioner used to sign the certificate.",
			},
			"provisioner_password_wo": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				WriteOnly:   true,
				Description: "Password used to decrypt the JWK provisioner private key.",
			},
			"provisioner_password_version": schema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Version marker for provisioner password rotation. Bump this to force certificate re-issuance.",
			},
			"sans": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
				Description: "Additional Subject Alternative Names. The common name is always included.",
			},
			"not_after": schema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Requested certificate validity upper bound (for example `8760h`).",
			},
			"renewal_version": schema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Arbitrary marker to force certificate replacement.",
			},
			"certificate_pem": schema.StringAttribute{
				Computed:    true,
				Description: "Issued leaf certificate PEM.",
			},
			"certificate_chain_pem": schema.StringAttribute{
				Computed:    true,
				Description: "Issued certificate chain PEM (leaf first).",
			},
			"ca_pem": schema.StringAttribute{
				Computed:    true,
				Description: "CA chain PEM without the leaf certificate.",
			},
			"private_key_pem": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "Generated private key PEM for the issued certificate.",
			},
			"serial_number": schema.StringAttribute{
				Computed:    true,
				Description: "Issued certificate serial number.",
			},
			"not_before": schema.StringAttribute{
				Computed:    true,
				Description: "Certificate validity start (RFC3339).",
			},
			"expires_at": schema.StringAttribute{
				Computed:    true,
				Description: "Certificate validity end (RFC3339).",
			},
		},
	}
}

func (r *certificateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*stepAPIClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("Expected *stepAPIClient, got: %T", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *certificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan certificateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var config certificateResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ProvisionerPassword = config.ProvisionerPassword

	sans := make([]string, 0)
	resp.Diagnostics.Append(plan.SANs.ElementsAs(ctx, &sans, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	issued, err := r.client.issueCertificate(ctx, issueCertificateRequest{
		CommonName:          plan.CommonName.ValueString(),
		SANs:                sans,
		Provisioner:         plan.ProvisionerName.ValueString(),
		ProvisionerPassword: plan.ProvisionerPassword.ValueString(),
		NotAfter:            plan.NotAfter.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to issue certificate", err.Error())
		return
	}

	plan.ID = types.StringValue(issued.SerialNumber)
	plan.CertificatePEM = types.StringValue(issued.LeafPEM)
	plan.CertificateChainPEM = types.StringValue(issued.CertChainPEM)
	plan.CAPEM = types.StringValue(issued.CaPEM)
	plan.PrivateKeyPEM = types.StringValue(issued.PrivateKeyPEM)
	plan.SerialNumber = types.StringValue(issued.SerialNumber)
	plan.NotBefore = types.StringValue(issued.NotBefore.UTC().Format("2006-01-02T15:04:05Z"))
	plan.ExpiresAt = types.StringValue(issued.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
	plan.ProvisionerPassword = types.StringNull()

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *certificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state certificateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.ProvisionerPassword = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *certificateResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"Unsupported operation",
		"Certificate updates are not supported. Change an input attribute to replace the resource.",
	)
}

func (r *certificateResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
	// Step CA has no delete API for issued certificates. Removing from Terraform state is enough.
}
