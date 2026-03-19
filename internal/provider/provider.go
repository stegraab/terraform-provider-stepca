package provider

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = &stepCAProvider{}

type stepCAProvider struct {
	version string
}

type stepCAProviderModel struct {
	URL                types.String `tfsdk:"url"`
	Token              types.String `tfsdk:"token"`
	AdminProvisioner   types.String `tfsdk:"admin_provisioner"`
	AdminSubject       types.String `tfsdk:"admin_subject"`
	AdminPassword      types.String `tfsdk:"admin_password"`
	InsecureSkipVerify types.Bool   `tfsdk:"insecure_skip_verify"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &stepCAProvider{version: version}
	}
}

func (p *stepCAProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "stepca"
	resp.Version = p.version
}

func (p *stepCAProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Optional:    true,
				Description: "Step CA base URL (for example https://ca.example.com). Can also be set via STEPCA_URL.",
			},
			"token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Admin API JWT token for direct authentication. Can also be set via STEPCA_TOKEN.",
			},
			"admin_provisioner": schema.StringAttribute{
				Optional:    true,
				Description: "JWK provisioner name used to mint admin credentials (for example 'Admin JWK'). Can also be set via STEPCA_ADMIN_PROVISIONER.",
			},
			"admin_subject": schema.StringAttribute{
				Optional:    true,
				Description: "Admin subject used to mint an ephemeral admin certificate. Can also be set via STEPCA_ADMIN_SUBJECT.",
			},
			"admin_password": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Password used to decrypt the JWK provisioner private key. Can also be set via STEPCA_ADMIN_PASSWORD.",
			},
			"insecure_skip_verify": schema.BoolAttribute{
				Optional:    true,
				Description: "Disable TLS certificate verification for Step CA requests. Can also be set via STEPCA_INSECURE_SKIP_VERIFY.",
			},
		},
	}
}

func (p *stepCAProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data stepCAProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	url, ok := configString(data.URL, "STEPCA_URL", "")
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`url` is unknown")
		return
	}

	token, ok := configString(data.Token, "STEPCA_TOKEN", "")
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`token` is unknown")
		return
	}

	adminProvisioner, ok := configString(data.AdminProvisioner, "STEPCA_ADMIN_PROVISIONER", "")
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`admin_provisioner` is unknown")
		return
	}

	adminSubject, ok := configString(data.AdminSubject, "STEPCA_ADMIN_SUBJECT", "")
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`admin_subject` is unknown")
		return
	}

	adminPassword, ok := configString(data.AdminPassword, "STEPCA_ADMIN_PASSWORD", "")
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`admin_password` is unknown")
		return
	}

	insecureSkipVerify, ok := configBool(data.InsecureSkipVerify, "STEPCA_INSECURE_SKIP_VERIFY", false)
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`insecure_skip_verify` is unknown")
		return
	}

	if url == "" {
		resp.Diagnostics.AddError("Missing provider configuration", "`url` must be set in provider config or STEPCA_URL")
		return
	}

	hasToken := strings.TrimSpace(token) != ""
	hasJWKAuth := strings.TrimSpace(adminProvisioner) != "" || strings.TrimSpace(adminSubject) != "" || strings.TrimSpace(adminPassword) != ""

	if !hasToken && !hasJWKAuth {
		resp.Diagnostics.AddError(
			"Missing provider authentication",
			"Set either `token` (or STEPCA_TOKEN), or set all of: `admin_provisioner`, `admin_subject`, and `admin_password`.",
		)
		return
	}

	if hasToken && hasJWKAuth {
		resp.Diagnostics.AddError(
			"Ambiguous provider authentication",
			"Set either `token` OR JWK auth fields (`admin_provisioner`, `admin_subject`, `admin_password`), not both.",
		)
		return
	}

	if !hasToken {
		if strings.TrimSpace(adminProvisioner) == "" || strings.TrimSpace(adminSubject) == "" || strings.TrimSpace(adminPassword) == "" {
			resp.Diagnostics.AddError(
				"Incomplete JWK authentication",
				"When not using `token`, all JWK auth fields are required: `admin_provisioner`, `admin_subject`, `admin_password`.",
			)
			return
		}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecureSkipVerify}

	client := &stepAPIClient{
		baseURL:          normalizeBaseURL(url),
		token:            strings.TrimSpace(token),
		adminProvisioner: strings.TrimSpace(adminProvisioner),
		adminSubject:     strings.TrimSpace(adminSubject),
		adminPassword:    adminPassword,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}

	if hasToken {
		client.authMode = authModeToken
	} else {
		client.authMode = authModeJWK
	}

	resp.ResourceData = client
}

func (p *stepCAProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewProvisionerResource,
		NewCertificateResource,
	}
}

func (p *stepCAProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func normalizeBaseURL(raw string) string {
	u := strings.TrimSpace(raw)
	u = strings.TrimRight(u, "/")
	if strings.HasSuffix(u, "/admin") {
		u = strings.TrimSuffix(u, "/admin")
	}
	return u
}

func configString(v types.String, envVar string, defaultValue string) (string, bool) {
	if v.IsUnknown() {
		return "", false
	}

	if !v.IsNull() && v.ValueString() != "" {
		return v.ValueString(), true
	}

	if envValue, ok := os.LookupEnv(envVar); ok && envValue != "" {
		return envValue, true
	}

	return defaultValue, true
}

func configBool(v types.Bool, envVar string, defaultValue bool) (bool, bool) {
	if v.IsUnknown() {
		return false, false
	}

	if !v.IsNull() {
		return v.ValueBool(), true
	}

	if envValue, ok := os.LookupEnv(envVar); ok && envValue != "" {
		parsed, err := strconv.ParseBool(envValue)
		if err == nil {
			return parsed, true
		}
	}

	return defaultValue, true
}
