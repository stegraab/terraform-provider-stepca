---
page_title: "stepca_machine_enrollment Resource"
---

# stepca_machine_enrollment Resource

Registers expected platform identity with the machine-enrollment service before
a guest proves possession of its hardware-backed identity. Registration intent
is not attestation: the service must still verify live platform inventory and a
nonce-bound proof before issuing certificates.

```hcl
resource "stepca_machine_enrollment" "vm" {
  attestor_type     = "nutanix-vtpm"
  attestor_identity = nutanix_virtual_machine_v2.vm.ext_id
  attestor_claims = {
    generation_uuid = nutanix_virtual_machine_v2.vm.generation_uuid
    vtpm_disk_id     = nutanix_virtual_machine_v2.vm.vtpm_disk_id
  }

  machine_identity = "host/example.internal"
  ssh_principals   = ["example", "example.internal"]
}
```

`attestor_type`, `attestor_identity`, and `attestor_claims` keep the enrollment
contract independent of Nutanix. Future VMware, physical TPM, and cloud-instance
attestors can use the same resource lifecycle.

All configurable attributes are replace-only. Destroying or replacing the
resource revokes the registration while retaining the server-side audit record.

## Arguments

- `attestor_type` — platform attestor type, initially `nutanix-vtpm`.
- `attestor_identity` — stable inventory identity within that type.
- `attestor_claims` — expected string claims checked during attestation.
- `machine_identity` — requested machine identity subject.
- `ssh_principals` — requested SSH host principals, subject to server policy.

## Read-only attributes

- `id` — enrollment registration identifier.
- `status` — lifecycle status returned by the enrollment service.
