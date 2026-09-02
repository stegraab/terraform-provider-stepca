---
page_title: "stepca_provisioner Resource"
subcategory: ""
description: |-
  Manages a Step CA provisioner.
---

# stepca_provisioner Resource

Manages Step CA provisioners such as `JWK`, `OIDC`, `ACME`, and `SSHPOP`.

## Example Usage

```terraform
resource "stepca_provisioner" "oidc" {
  name = "oidc"
  type = "OIDC"

  claims_ssh_enabled  = true
  claims_x509_enabled = false

  ssh = {
    template = file("${path.module}/templates/ssh.gotpl")
  }

  oidc = {
    client_id              = "step-ca"
    client_secret          = var.oidc_client_secret
    configuration_endpoint = "https://auth.example.com/.well-known/openid-configuration"
    groups                 = ["admins"]
  }
}
```

Create a JWK provisioner that publishes only its public key. The private JWK is
ephemeral and can also be written to a secret store through a write-only
argument without entering Terraform state:

```hcl
ephemeral "stepca_jwk_key" "machine_enrollment" {}

resource "stepca_provisioner" "machine_enrollment" {
  name                    = "machine-enrollment"
  type                    = "JWK"
  jwk_private_key_wo      = ephemeral.stepca_jwk_key.machine_enrollment.private_key
  jwk_private_key_version = "1"

  claims_ssh_enabled  = true
  claims_x509_enabled = false
}
```

## Schema

### Required

- `name` (String) Provisioner name.
- `type` (String) Provisioner type (`JWK`, `OIDC`, `ACME`, `SSHPOP`, ...).

### Optional

- `x509` (Attributes) X.509 template block.
- `ssh` (Attributes) SSH template block.
- `oidc` (Attributes) OIDC configuration block.
- `acme_force_cn` (Boolean)
- `acme_require_eab` (Boolean)
- `acme_challenges` (List of String)
- `x509_min_dur` (String)
- `x509_max_dur` (String)
- `x509_default_dur` (String)
- `ssh_user_min_dur` (String)
- `ssh_user_max_dur` (String)
- `ssh_user_default_dur` (String)
- `ssh_host_min_dur` (String)
- `ssh_host_max_dur` (String)
- `ssh_host_default_dur` (String)
- `claims_disable_renewal` (Boolean)
- `claims_allow_renewal_after_expiry` (Boolean)
- `claims_disable_smallstep_extensions` (Boolean)
- `claims_ssh_enabled` (Boolean)
- `claims_x509_enabled` (Boolean)
- `jwk_password_wo` (String, Sensitive, Write-Only) Password used to create encrypted JWK keys.
- `jwk_password_version` (String) Version marker for JWK password rotation; bump to force replacement.
- `jwk_private_key_wo` (String, Sensitive, Write-Only) Private JWK used to create a public-key-only provisioner. It is never sent to Step CA or stored in state. Mutually exclusive with `jwk_password_wo`.
- `jwk_private_key_version` (String) Version marker for private JWK rotation; bump to force replacement.

### Read-Only

- `id` (String) Resource ID (same value as `name`).

### Nested Schema for `x509`

Optional:

- `template` (String) X.509 template string.

### Nested Schema for `ssh`

Optional:

- `template` (String) SSH template string.

### Nested Schema for `oidc`

Optional:

- `client_id` (String)
- `client_secret` (String, Sensitive)
- `configuration_endpoint` (String)
- `groups` (Set of String)

## Import

Import is supported by provisioner name:

```bash
terraform import stepca_provisioner.example my-provisioner-name
```
