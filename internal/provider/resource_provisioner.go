package provider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"go.step.sm/crypto/jose"
)

var (
	_ resource.Resource                = &provisionerResource{}
	_ resource.ResourceWithConfigure   = &provisionerResource{}
	_ resource.ResourceWithImportState = &provisionerResource{}
)

type provisionerResource struct {
	client *stepAPIClient
}

type provisionerTemplateBlockModel struct {
	Template types.String `tfsdk:"template"`
}

type provisionerOIDCBlockModel struct {
	ClientID              types.String `tfsdk:"client_id"`
	ClientSecret          types.String `tfsdk:"client_secret"`
	ConfigurationEndpoint types.String `tfsdk:"configuration_endpoint"`
	Groups                types.Set    `tfsdk:"groups"`
}

type provisionerResourceModel struct {
	ID                              types.String `tfsdk:"id"`
	Name                            types.String `tfsdk:"name"`
	Type                            types.String `tfsdk:"type"`
	X509                            types.Object `tfsdk:"x509"`
	SSH                             types.Object `tfsdk:"ssh"`
	OIDC                            types.Object `tfsdk:"oidc"`
	ACMEForceCN                     types.Bool   `tfsdk:"acme_force_cn"`
	ACMERequireEAB                  types.Bool   `tfsdk:"acme_require_eab"`
	ACMEChallenges                  types.List   `tfsdk:"acme_challenges"`
	X509MinDur                      types.String `tfsdk:"x509_min_dur"`
	X509MaxDur                      types.String `tfsdk:"x509_max_dur"`
	X509DefaultDur                  types.String `tfsdk:"x509_default_dur"`
	SSHUserMinDur                   types.String `tfsdk:"ssh_user_min_dur"`
	SSHUserMaxDur                   types.String `tfsdk:"ssh_user_max_dur"`
	SSHUserDefaultDur               types.String `tfsdk:"ssh_user_default_dur"`
	SSHHostMinDur                   types.String `tfsdk:"ssh_host_min_dur"`
	SSHHostMaxDur                   types.String `tfsdk:"ssh_host_max_dur"`
	SSHHostDefaultDur               types.String `tfsdk:"ssh_host_default_dur"`
	ClaimsDisableRenewal            types.Bool   `tfsdk:"claims_disable_renewal"`
	ClaimsAllowRenewalAfterExpiry   types.Bool   `tfsdk:"claims_allow_renewal_after_expiry"`
	ClaimsDisableSmallstepExtension types.Bool   `tfsdk:"claims_disable_smallstep_extensions"`
	ClaimsSSHEnabled                types.Bool   `tfsdk:"claims_ssh_enabled"`
	ClaimsX509Enabled               types.Bool   `tfsdk:"claims_x509_enabled"`
	JWKPassword                     types.String `tfsdk:"jwk_password_wo"`
	JWKPasswordVersion              types.String `tfsdk:"jwk_password_version"`
}

func NewProvisionerResource() resource.Resource {
	return &provisionerResource{}
}

func (r *provisionerResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_provisioner"
}

func (r *provisionerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Provisioner name.",
			},
			"type": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Provisioner type (for example JWK, OIDC, ACME, SSHPOP).",
			},
			"x509": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"template": schema.StringAttribute{
						Optional:    true,
						Description: "X.509 template string.",
					},
				},
			},
			"ssh": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"template": schema.StringAttribute{
						Optional:    true,
						Description: "SSH template string.",
					},
				},
			},
			"oidc": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"client_id":              schema.StringAttribute{Optional: true},
					"client_secret":          schema.StringAttribute{Optional: true, Sensitive: true},
					"configuration_endpoint": schema.StringAttribute{Optional: true},
					"groups":                 schema.SetAttribute{Optional: true, ElementType: types.StringType},
				},
			},
			"acme_force_cn":                       schema.BoolAttribute{Optional: true},
			"acme_require_eab":                    schema.BoolAttribute{Optional: true},
			"acme_challenges":                     schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"x509_min_dur":                        schema.StringAttribute{Optional: true},
			"x509_max_dur":                        schema.StringAttribute{Optional: true},
			"x509_default_dur":                    schema.StringAttribute{Optional: true},
			"ssh_user_min_dur":                    schema.StringAttribute{Optional: true},
			"ssh_user_max_dur":                    schema.StringAttribute{Optional: true},
			"ssh_user_default_dur":                schema.StringAttribute{Optional: true},
			"ssh_host_min_dur":                    schema.StringAttribute{Optional: true},
			"ssh_host_max_dur":                    schema.StringAttribute{Optional: true},
			"ssh_host_default_dur":                schema.StringAttribute{Optional: true},
			"claims_disable_renewal":              schema.BoolAttribute{Optional: true},
			"claims_allow_renewal_after_expiry":   schema.BoolAttribute{Optional: true},
			"claims_disable_smallstep_extensions": schema.BoolAttribute{Optional: true},
			"claims_ssh_enabled":                  schema.BoolAttribute{Optional: true},
			"claims_x509_enabled":                 schema.BoolAttribute{Optional: true},
			"jwk_password_wo": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
			},
			"jwk_password_version": schema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Version marker for JWK password rotation. Bump this value to force resource replacement.",
			},
		},
	}
}

func (r *provisionerResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *provisionerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan provisionerResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var config provisionerResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.JWKPassword = config.JWKPassword

	desired, ok := buildDesiredProvisioner(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}

	existing, found, err := r.client.getProvisioner(ctx, plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read provisioner", err.Error())
		return
	}

	if !found {
		if isType(plan.Type, "JWK") {
			if _, ok := desired["details"]; !ok {
				resp.Diagnostics.AddError("Failed to create provisioner", "JWK provisioner creation requires `jwk_password_wo`.")
				return
			}
		}
		if err := r.client.createProvisioner(ctx, desired); err != nil {
			resp.Diagnostics.AddError("Failed to create provisioner", err.Error())
			return
		}
	} else {
		if isType(plan.Type, "JWK") {
			// Keep existing key material on update unless explicitly rekey support is added.
			delete(desired, "details")
		}
		updatePayload, err := buildUpdatePayload(existing, desired, plan.Name.ValueString(), plan.Type.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Failed to build update payload", err.Error())
			return
		}
		if err := r.client.updateProvisioner(ctx, plan.Name.ValueString(), updatePayload); err != nil {
			resp.Diagnostics.AddError("Failed to create provisioner", err.Error())
			return
		}
	}

	plan.ID = plan.Name
	plan.JWKPassword = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *provisionerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state provisionerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	existing, found, err := r.client.getProvisioner(ctx, state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read provisioner", err.Error())
		return
	}

	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = state.Name
	state.JWKPassword = types.StringNull()
	if t, ok := existing["type"].(string); ok && t != "" {
		state.Type = types.StringValue(t)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *provisionerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan provisionerResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var config provisionerResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.JWKPassword = config.JWKPassword

	desired, ok := buildDesiredProvisioner(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}

	existing, found, err := r.client.getProvisioner(ctx, plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read provisioner", err.Error())
		return
	}

	if !found {
		if isType(plan.Type, "JWK") {
			if _, ok := desired["details"]; !ok {
				resp.Diagnostics.AddError("Failed to create provisioner", "JWK provisioner creation requires `jwk_password_wo`.")
				return
			}
		}
		if err := r.client.createProvisioner(ctx, desired); err != nil {
			resp.Diagnostics.AddError("Failed to create provisioner", err.Error())
			return
		}
	} else {
		if isType(plan.Type, "JWK") {
			delete(desired, "details")
		}
		updatePayload, err := buildUpdatePayload(existing, desired, plan.Name.ValueString(), plan.Type.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Failed to build update payload", err.Error())
			return
		}
		if err := r.client.updateProvisioner(ctx, plan.Name.ValueString(), updatePayload); err != nil {
			resp.Diagnostics.AddError("Failed to update provisioner", err.Error())
			return
		}
	}

	plan.ID = plan.Name
	plan.JWKPassword = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *provisionerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state provisionerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.deleteProvisioner(ctx, state.Name.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to delete provisioner", err.Error())
	}
}

func (r *provisionerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

func buildDesiredProvisioner(ctx context.Context, plan provisionerResourceModel, diags *diag.Diagnostics) (map[string]any, bool) {
	desired := map[string]any{
		"name": plan.Name.ValueString(),
		"type": plan.Type.ValueString(),
	}

	x509, ok := decodeTemplateBlock(ctx, plan.X509, diags)
	if !ok {
		return nil, false
	}
	ssh, ok := decodeTemplateBlock(ctx, plan.SSH, diags)
	if !ok {
		return nil, false
	}
	oidcBlock, ok := decodeOIDCBlock(ctx, plan.OIDC, diags)
	if !ok {
		return nil, false
	}

	putTemplate(desired, "x509Template", x509.Template)
	putTemplate(desired, "sshTemplate", ssh.Template)

	claims := map[string]any{}
	addOptionalBool(claims, "disableRenewal", plan.ClaimsDisableRenewal)
	addOptionalBool(claims, "allowRenewalAfterExpiry", plan.ClaimsAllowRenewalAfterExpiry)
	addOptionalBool(claims, "disableSmallstepExtensions", plan.ClaimsDisableSmallstepExtension)

	x509Durations := map[string]any{}
	if setOptionalDuration(x509Durations, "min", plan.X509MinDur) ||
		setOptionalDuration(x509Durations, "max", plan.X509MaxDur) ||
		setOptionalDuration(x509Durations, "default", plan.X509DefaultDur) {
		x := ensureObject(claims, "x509")
		x["durations"] = x509Durations
	}
	if !plan.ClaimsX509Enabled.IsNull() && !plan.ClaimsX509Enabled.IsUnknown() {
		x := ensureObject(claims, "x509")
		x["enabled"] = plan.ClaimsX509Enabled.ValueBool()
	}

	sshUserDurations := map[string]any{}
	if setOptionalDuration(sshUserDurations, "min", plan.SSHUserMinDur) ||
		setOptionalDuration(sshUserDurations, "max", plan.SSHUserMaxDur) ||
		setOptionalDuration(sshUserDurations, "default", plan.SSHUserDefaultDur) {
		s := ensureObject(claims, "ssh")
		s["userDurations"] = sshUserDurations
	}

	sshHostDurations := map[string]any{}
	if setOptionalDuration(sshHostDurations, "min", plan.SSHHostMinDur) ||
		setOptionalDuration(sshHostDurations, "max", plan.SSHHostMaxDur) ||
		setOptionalDuration(sshHostDurations, "default", plan.SSHHostDefaultDur) {
		s := ensureObject(claims, "ssh")
		s["hostDurations"] = sshHostDurations
	}
	if !plan.ClaimsSSHEnabled.IsNull() && !plan.ClaimsSSHEnabled.IsUnknown() {
		s := ensureObject(claims, "ssh")
		s["enabled"] = plan.ClaimsSSHEnabled.ValueBool()
	}

	if len(claims) > 0 {
		desired["claims"] = claims
	}

	if isType(plan.Type, "OIDC") {
		oidc := map[string]any{}
		addOptionalStringValue(oidc, "clientId", oidcBlock.ClientID)
		addOptionalStringValue(oidc, "clientSecret", oidcBlock.ClientSecret)
		addOptionalStringValue(oidc, "configurationEndpoint", oidcBlock.ConfigurationEndpoint)
		if groups, ok := decodeSetStrings(ctx, oidcBlock.Groups, diags); ok && len(groups) > 0 {
			oidc["groups"] = groups
		} else if !ok {
			return nil, false
		}
		if len(oidc) > 0 {
			desired["details"] = map[string]any{
				"OIDC": oidc,
			}
		}
	}

	if isType(plan.Type, "ACME") {
		acme := map[string]any{}
		if !plan.ACMEForceCN.IsNull() && !plan.ACMEForceCN.IsUnknown() {
			acme["forceCn"] = plan.ACMEForceCN.ValueBool()
		}
		if !plan.ACMERequireEAB.IsNull() && !plan.ACMERequireEAB.IsUnknown() {
			acme["requireEab"] = plan.ACMERequireEAB.ValueBool()
		}
		if challenges, ok := decodeListStrings(ctx, plan.ACMEChallenges, diags); ok && len(challenges) > 0 {
			acme["challenges"] = challenges
		} else if !ok {
			return nil, false
		}
		desired["details"] = map[string]any{
			"ACME": acme,
		}
	}

	if isType(plan.Type, "SSHPOP") {
		desired["details"] = map[string]any{
			"SSHPOP": map[string]any{},
		}
	}

	if isType(plan.Type, "JWK") {
		password := strings.TrimSpace(stringValue(plan.JWKPassword))
		if password != "" {
			details, err := buildJWKDetails(password)
			if err != nil {
				diags.AddError("Invalid JWK provisioner configuration", err.Error())
				return nil, false
			}
			desired["details"] = details
		}
	}

	return desired, true
}

func buildJWKDetails(password string) (map[string]any, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate JWK private key: %w", err)
	}

	privateJWK := jose.JSONWebKey{
		Key:       privateKey,
		Use:       "sig",
		Algorithm: jose.ES256,
	}

	thumbprint, err := privateJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("compute JWK thumbprint: %w", err)
	}
	privateJWK.KeyID = base64.RawURLEncoding.EncodeToString(thumbprint)

	publicJWK := privateJWK.Public()
	publicJSON, err := json.Marshal(publicJWK)
	if err != nil {
		return nil, fmt.Errorf("marshal JWK public key: %w", err)
	}

	privateJSON, err := json.Marshal(privateJWK)
	if err != nil {
		return nil, fmt.Errorf("marshal JWK private key: %w", err)
	}

	encrypted, err := jose.Encrypt(privateJSON, jose.WithPassword([]byte(password)))
	if err != nil {
		return nil, fmt.Errorf("encrypt JWK private key: %w", err)
	}
	encryptedCompact, err := encrypted.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("serialize encrypted JWK: %w", err)
	}

	return map[string]any{
		"JWK": map[string]any{
			"publicKey":           base64.StdEncoding.EncodeToString(publicJSON),
			"encryptedPrivateKey": base64.StdEncoding.EncodeToString([]byte(encryptedCompact)),
		},
	}, nil
}

func isType(t types.String, expected string) bool {
	return strings.EqualFold(strings.TrimSpace(t.ValueString()), expected)
}

func putTemplate(dst map[string]any, key string, tmpl types.String) {
	t := strings.TrimSpace(stringValue(tmpl))
	if t == "" {
		return
	}
	dst[key] = map[string]any{"template": base64.StdEncoding.EncodeToString([]byte(t))}
}

func ensureObject(root map[string]any, key string) map[string]any {
	m, ok := root[key].(map[string]any)
	if !ok {
		m = map[string]any{}
		root[key] = m
	}
	return m
}

func addOptionalBool(m map[string]any, key string, v types.Bool) {
	if v.IsNull() || v.IsUnknown() {
		return
	}
	m[key] = v.ValueBool()
}

func setOptionalDuration(m map[string]any, key string, v types.String) bool {
	value := strings.TrimSpace(stringValue(v))
	if value == "" {
		return false
	}
	m[key] = value
	return true
}

func addOptionalStringValue(m map[string]any, key string, v types.String) {
	value := strings.TrimSpace(stringValue(v))
	if value == "" {
		return
	}
	m[key] = value
}

func stringValue(v types.String) string {
	if v.IsNull() || v.IsUnknown() {
		return ""
	}
	return v.ValueString()
}

func decodeSetStrings(ctx context.Context, set types.Set, diags *diag.Diagnostics) ([]string, bool) {
	if set.IsNull() || set.IsUnknown() {
		return nil, true
	}
	var out []string
	diags.Append(set.ElementsAs(ctx, &out, false)...)
	if diags.HasError() {
		return nil, false
	}
	return out, true
}

func decodeListStrings(ctx context.Context, list types.List, diags *diag.Diagnostics) ([]string, bool) {
	if list.IsNull() || list.IsUnknown() {
		return nil, true
	}
	var out []string
	diags.Append(list.ElementsAs(ctx, &out, false)...)
	if diags.HasError() {
		return nil, false
	}
	return out, true
}

func decodeTemplateBlock(ctx context.Context, obj types.Object, diags *diag.Diagnostics) (provisionerTemplateBlockModel, bool) {
	if obj.IsNull() || obj.IsUnknown() {
		return provisionerTemplateBlockModel{}, true
	}
	var out provisionerTemplateBlockModel
	diags.Append(obj.As(ctx, &out, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return provisionerTemplateBlockModel{}, false
	}
	return out, true
}

func decodeOIDCBlock(ctx context.Context, obj types.Object, diags *diag.Diagnostics) (provisionerOIDCBlockModel, bool) {
	if obj.IsNull() || obj.IsUnknown() {
		return provisionerOIDCBlockModel{}, true
	}
	var out provisionerOIDCBlockModel
	diags.Append(obj.As(ctx, &out, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return provisionerOIDCBlockModel{}, false
	}
	return out, true
}

func buildUpdatePayload(existing map[string]any, desired map[string]any, name string, provisionerType string) (map[string]any, error) {
	payload, err := deepCopyMap(existing)
	if err != nil {
		return nil, err
	}

	mergeMaps(payload, desired)

	// Template blocks are optional in Terraform config. If omitted, clear the
	// corresponding template in Step CA instead of retaining the previous value.
	if _, ok := desired["x509Template"]; !ok {
		delete(payload, "x509Template")
	}
	if _, ok := desired["sshTemplate"]; !ok {
		delete(payload, "sshTemplate")
	}

	payload["name"] = name
	payload["type"] = provisionerType

	for _, key := range []string{"id", "authorityId", "createdAt", "deletedAt"} {
		if value, ok := existing[key]; ok {
			payload[key] = value
		}
	}

	return payload, nil
}

func deepCopyMap(input map[string]any) (map[string]any, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal map: %w", err)
	}

	var copied map[string]any
	if err := json.Unmarshal(encoded, &copied); err != nil {
		return nil, fmt.Errorf("unmarshal map: %w", err)
	}
	return copied, nil
}

func mergeMaps(dst map[string]any, src map[string]any) {
	for key, srcValue := range src {
		srcMap, srcIsMap := srcValue.(map[string]any)
		dstValue, dstHasKey := dst[key]
		dstMap, dstIsMap := dstValue.(map[string]any)

		if srcIsMap && dstHasKey && dstIsMap {
			mergeMaps(dstMap, srcMap)
			continue
		}

		dst[key] = srcValue
	}
}
