package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"go.step.sm/crypto/jose"
)

func TestBuildDesiredProvisionerOIDC(t *testing.T) {
	t.Parallel()

	oidc := types.ObjectValueMust(
		map[string]attr.Type{
			"client_id":              types.StringType,
			"client_secret":          types.StringType,
			"configuration_endpoint": types.StringType,
			"groups":                 types.SetType{ElemType: types.StringType},
		},
		map[string]attr.Value{
			"client_id":              types.StringValue("step-ca"),
			"client_secret":          types.StringValue("secret"),
			"configuration_endpoint": types.StringValue("https://issuer/.well-known/openid-configuration"),
			"groups":                 types.SetValueMust(types.StringType, []attr.Value{types.StringValue("admins")}),
		},
	)

	plan := provisionerResourceModel{
		Name: types.StringValue("oidc"),
		Type: types.StringValue("OIDC"),
		OIDC: oidc,
	}

	var diags diag.Diagnostics
	desired, ok := buildDesiredProvisioner(context.Background(), plan, &diags)
	if !ok {
		t.Fatalf("expected ok=true, got false with diagnostics: %+v", diags)
	}
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}

	if desired["name"] != "oidc" {
		t.Fatalf("name mismatch: %#v", desired["name"])
	}
	if desired["type"] != "OIDC" {
		t.Fatalf("type mismatch: %#v", desired["type"])
	}

	details, ok := desired["details"].(map[string]any)
	if !ok {
		t.Fatalf("expected details map, got: %#v", desired["details"])
	}
	oidcDetails, ok := details["OIDC"].(map[string]any)
	if !ok {
		t.Fatalf("expected OIDC details map, got: %#v", details["OIDC"])
	}

	if oidcDetails["clientId"] != "step-ca" {
		t.Fatalf("clientId mismatch: %#v", oidcDetails["clientId"])
	}
	if oidcDetails["clientSecret"] != "secret" {
		t.Fatalf("clientSecret mismatch: %#v", oidcDetails["clientSecret"])
	}
	if oidcDetails["configurationEndpoint"] != "https://issuer/.well-known/openid-configuration" {
		t.Fatalf("configurationEndpoint mismatch: %#v", oidcDetails["configurationEndpoint"])
	}

	groups, ok := oidcDetails["groups"].([]string)
	if !ok || len(groups) != 1 || groups[0] != "admins" {
		t.Fatalf("groups mismatch: %#v", oidcDetails["groups"])
	}
}

func TestBuildJWKDetails(t *testing.T) {
	t.Parallel()

	details, err := buildJWKDetails("top-secret")
	if err != nil {
		t.Fatalf("buildJWKDetails returned error: %v", err)
	}

	jwkMap, ok := details["JWK"].(map[string]any)
	if !ok {
		t.Fatalf("expected JWK map, got %#v", details["JWK"])
	}

	publicKey, ok := jwkMap["publicKey"].(string)
	if !ok || publicKey == "" {
		t.Fatalf("missing publicKey: %#v", jwkMap["publicKey"])
	}
	if _, err := base64.StdEncoding.DecodeString(publicKey); err != nil {
		t.Fatalf("publicKey is not valid base64: %v", err)
	}

	encryptedPrivateKey, ok := jwkMap["encryptedPrivateKey"].(string)
	if !ok || encryptedPrivateKey == "" {
		t.Fatalf("missing encryptedPrivateKey: %#v", jwkMap["encryptedPrivateKey"])
	}
	if _, err := base64.StdEncoding.DecodeString(encryptedPrivateKey); err != nil {
		t.Fatalf("encryptedPrivateKey is not valid base64: %v", err)
	}
}

func TestBuildPublicJWKDetailsOmitsEncryptedPrivateKey(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	privateJWK := jose.JSONWebKey{
		Key:       key,
		KeyID:     "machine-enrollment-test",
		Use:       "sig",
		Algorithm: jose.ES256,
	}
	privateJSON, err := json.Marshal(privateJWK)
	if err != nil {
		t.Fatalf("marshal private JWK: %v", err)
	}

	details, err := buildPublicJWKDetails(string(privateJSON))
	if err != nil {
		t.Fatalf("buildPublicJWKDetails returned error: %v", err)
	}
	jwkMap, ok := details["JWK"].(map[string]any)
	if !ok {
		t.Fatalf("expected JWK map, got %#v", details["JWK"])
	}
	if _, exists := jwkMap["encryptedPrivateKey"]; exists {
		t.Fatal("public-key-only provisioner must not include encryptedPrivateKey")
	}

	encodedPublicKey, ok := jwkMap["publicKey"].(string)
	if !ok || encodedPublicKey == "" {
		t.Fatalf("missing publicKey: %#v", jwkMap["publicKey"])
	}
	publicJSON, err := base64.StdEncoding.DecodeString(encodedPublicKey)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	var publicJWK jose.JSONWebKey
	if err := json.Unmarshal(publicJSON, &publicJWK); err != nil {
		t.Fatalf("unmarshal public JWK: %v", err)
	}
	if !publicJWK.Valid() || !publicJWK.IsPublic() {
		t.Fatal("provisioner publicKey must be a valid public JWK")
	}
	if publicJWK.KeyID != privateJWK.KeyID {
		t.Fatalf("key ID mismatch: got %q, want %q", publicJWK.KeyID, privateJWK.KeyID)
	}
}

func TestBuildDesiredProvisionerRejectsBothJWKAuthenticationModes(t *testing.T) {
	t.Parallel()

	plan := provisionerResourceModel{
		Name:          types.StringValue("machine-enrollment"),
		Type:          types.StringValue("JWK"),
		JWKPassword:   types.StringValue("password"),
		JWKPrivateKey: types.StringValue("private-key"),
	}
	var diags diag.Diagnostics
	_, ok := buildDesiredProvisioner(context.Background(), plan, &diags)
	if ok || !diags.HasError() {
		t.Fatalf("expected mutually exclusive JWK authentication modes to fail: %+v", diags)
	}
}

func TestBuildUpdatePayloadClearsOmittedTemplates(t *testing.T) {
	t.Parallel()

	existing := map[string]any{
		"id":   "provisioner-id",
		"name": "old-name",
		"type": "OIDC",
		"x509Template": map[string]any{
			"template": "old-x509",
		},
		"sshTemplate": map[string]any{
			"template": "old-ssh",
		},
	}
	desired := map[string]any{
		"details": map[string]any{
			"OIDC": map[string]any{"clientId": "step-ca"},
		},
	}

	payload, err := buildUpdatePayload(existing, desired, "new-name", "OIDC")
	if err != nil {
		t.Fatalf("buildUpdatePayload returned error: %v", err)
	}

	if _, ok := payload["x509Template"]; ok {
		t.Fatalf("expected x509Template to be removed when omitted in desired payload")
	}
	if _, ok := payload["sshTemplate"]; ok {
		t.Fatalf("expected sshTemplate to be removed when omitted in desired payload")
	}
	if payload["name"] != "new-name" {
		t.Fatalf("name mismatch: %#v", payload["name"])
	}
	if payload["type"] != "OIDC" {
		t.Fatalf("type mismatch: %#v", payload["type"])
	}
	if payload["id"] != "provisioner-id" {
		t.Fatalf("id should be preserved: %#v", payload["id"])
	}
}
