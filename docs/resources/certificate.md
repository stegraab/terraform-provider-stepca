---
page_title: "stepca_certificate Resource"
subcategory: ""
description: |-
  Issues an X.509 certificate from a JWK provisioner.
---

# stepca_certificate Resource

Issues an X.509 certificate by:

1. Decrypting the specified JWK provisioner key with `provisioner_password_wo`.
2. Minting a short-lived OTT for `/1.0/sign`.
3. Generating a new private key and CSR.
4. Requesting certificate issuance from Step CA.

This resource is replace-only. Changing inputs re-issues the certificate.

## Example Usage

```terraform
resource "stepca_certificate" "middleware_tls" {
  common_name                  = "ca.example.internal"
  provisioner_name             = "Admin JWK"
  provisioner_password_wo      = var.admin_jwk_password
  provisioner_password_version = "1"
  sans                         = ["10.0.0.15", "ca.example.internal"]
  not_after                    = "8760h"
}
```

## Schema

### Required

- `common_name` (String) Certificate subject common name.
- `provisioner_name` (String) JWK provisioner used to sign the certificate.
- `provisioner_password_wo` (String, Sensitive, Write-Only) Password used to decrypt the JWK provisioner private key.

### Optional

- `sans` (Set of String) Additional SAN values. `common_name` is always included.
- `not_after` (String) Requested certificate validity upper bound (for example `8760h`).
- `provisioner_password_version` (String) Version marker for password rotation. Bump to force replacement.
- `renewal_version` (String) Arbitrary marker to force replacement.

### Read-Only

- `id` (String) Same value as `serial_number`.
- `certificate_pem` (String) Issued leaf certificate PEM.
- `certificate_chain_pem` (String) Issued certificate chain PEM (leaf first).
- `ca_pem` (String) CA chain PEM without the leaf.
- `private_key_pem` (String, Sensitive) Generated private key PEM.
- `serial_number` (String) Issued certificate serial number.
- `not_before` (String) Certificate validity start in RFC3339.
- `expires_at` (String) Certificate validity end in RFC3339.
