---
page_title: "stepca_jwk_key Ephemeral Resource"
subcategory: ""
description: |-
  Generates an ephemeral ES256 JWK key pair without storing the private key in Terraform state.
---

# stepca_jwk_key (Ephemeral Resource)

Generates an ES256 JWK key pair for the duration of one Terraform operation.
Use `private_key` only with write-only arguments, such as
`stepca_provisioner.jwk_private_key_wo` and `aws_ssm_parameter.value_wo`.

```hcl
ephemeral "stepca_jwk_key" "machine_enrollment" {}

resource "stepca_provisioner" "machine_enrollment" {
  name                    = "machine-enrollment"
  type                    = "JWK"
  jwk_private_key_wo      = ephemeral.stepca_jwk_key.machine_enrollment.private_key
  jwk_private_key_version = "1"
}

resource "aws_ssm_parameter" "machine_enrollment_key" {
  name             = "/pki/machine-enrollment/provisioner-key"
  type             = "SecureString"
  value_wo         = ephemeral.stepca_jwk_key.machine_enrollment.private_key
  value_wo_version = 1
}
```

## Read-Only

- `private_key` (String, Sensitive) Private JWK JSON. The value is ephemeral and is never stored in Terraform state.
- `public_key` (String) Public JWK JSON.
