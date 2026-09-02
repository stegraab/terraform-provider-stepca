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

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"go.step.sm/crypto/jose"
)

var _ ephemeral.EphemeralResource = &jwkKeyEphemeralResource{}

type jwkKeyEphemeralResource struct{}

type jwkKeyEphemeralResourceModel struct {
	PrivateKey types.String `tfsdk:"private_key"`
	PublicKey  types.String `tfsdk:"public_key"`
}

func NewJWKKeyEphemeralResource() ephemeral.EphemeralResource {
	return &jwkKeyEphemeralResource{}
}

func (r *jwkKeyEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_jwk_key"
}

func (r *jwkKeyEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Generates an ephemeral ES256 JWK key pair. The private key exists only during the Terraform operation.",
		Attributes: map[string]schema.Attribute{
			"private_key": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "Private JWK JSON. Pass only to write-only arguments.",
			},
			"public_key": schema.StringAttribute{
				Computed:    true,
				Description: "Public JWK JSON.",
			},
		},
	}
}

func (r *jwkKeyEphemeralResource) Open(ctx context.Context, _ ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		resp.Diagnostics.AddError("Failed to generate JWK", fmt.Sprintf("generate ES256 private key: %v", err))
		return
	}

	privateJWK := jose.JSONWebKey{
		Key:       privateKey,
		Use:       "sig",
		Algorithm: jose.ES256,
	}
	thumbprint, err := privateJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		resp.Diagnostics.AddError("Failed to generate JWK", fmt.Sprintf("compute thumbprint: %v", err))
		return
	}
	privateJWK.KeyID = base64.RawURLEncoding.EncodeToString(thumbprint)

	privateJSON, err := json.Marshal(privateJWK)
	if err != nil {
		resp.Diagnostics.AddError("Failed to generate JWK", fmt.Sprintf("marshal private key: %v", err))
		return
	}
	publicJSON, err := json.Marshal(privateJWK.Public())
	if err != nil {
		resp.Diagnostics.AddError("Failed to generate JWK", fmt.Sprintf("marshal public key: %v", err))
		return
	}

	result := jwkKeyEphemeralResourceModel{
		PrivateKey: types.StringValue(string(privateJSON)),
		PublicKey:  types.StringValue(string(publicJSON)),
	}
	resp.Diagnostics.Append(resp.Result.Set(ctx, &result)...)
}
