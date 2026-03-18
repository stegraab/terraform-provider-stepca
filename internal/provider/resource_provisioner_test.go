package provider

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
