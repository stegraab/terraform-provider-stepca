---
page_title: "stepca Provider"
subcategory: ""
description: |-
  Terraform provider for managing Step CA provisioners.
---

# stepca Provider

Use the `stepca` provider to manage Step CA provisioners over the Step CA Admin API.

## Example Usage

```terraform
terraform {
  required_providers {
    stepca = {
      source  = "local/stepca"
      version = "0.0.1"
    }
  }
}

provider "stepca" {
  url = "https://ca.example.internal"

  # Use exactly one auth mode:
  # token = var.stepca_token

  admin_provisioner = "Admin JWK"
  admin_subject     = "step"
  admin_password    = var.stepca_admin_password
}
```

## Authentication

Configure exactly one auth mode:

- Token auth:
  - `token`
- JWK auth:
  - `admin_provisioner`
  - `admin_subject`
  - `admin_password`

## Schema

### Optional

- `url` (String) Step CA base URL (for example `https://ca.example.com`).
- `token` (String, Sensitive) Admin API JWT token for direct authentication.
- `admin_provisioner` (String) JWK provisioner name used to mint admin credentials.
- `admin_subject` (String) Admin subject used to mint an ephemeral admin certificate.
- `admin_password` (String, Sensitive) Password used to decrypt the JWK provisioner private key.
- `insecure_skip_verify` (Boolean) Disable TLS certificate verification for Step CA requests.

All attributes above can also be provided via environment variables:

- `STEPCA_URL`
- `STEPCA_TOKEN`
- `STEPCA_ADMIN_PROVISIONER`
- `STEPCA_ADMIN_SUBJECT`
- `STEPCA_ADMIN_PASSWORD`
- `STEPCA_INSECURE_SKIP_VERIFY`
