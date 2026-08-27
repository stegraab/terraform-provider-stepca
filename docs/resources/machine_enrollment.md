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
  attestor_identity = nutanix_virtual_machine_v2.vm.bios_uuid
  attestor_claims = {
    vm_ext_id       = nutanix_virtual_machine_v2.vm.ext_id
    generation_uuid = nutanix_virtual_machine_v2.vm.generation_uuid
    vtpm_disk_id     = nutanix_virtual_machine_v2.vm.vtpm_disk_id
    nic_ext_id       = nutanix_virtual_machine_v2.vm.nics[0].ext_id
    mac_address      = nutanix_virtual_machine_v2.vm.nics[0].nic_backing_info[0].virtual_ethernet_nic[0].mac_address
    ip_address       = nutanix_virtual_machine_v2.vm.nics[0].nic_network_info[0].virtual_ethernet_nic_network_info[0].ipv4_config[0].ip_address[0].value
  }

  machine_identity = "host/example.internal"
  ssh_principals   = ["example", "example.internal"]
}
```

`attestor_type`, `attestor_identity`, and `attestor_claims` keep the enrollment
contract independent of Nutanix. Future VMware, physical TPM, and cloud-instance
attestors can use the same resource lifecycle.

For `nutanix-vtpm`, the attestor identity is the BIOS UUID visible to the guest
through SMBIOS. The service requires `vm_ext_id`, `generation_uuid`,
`vtpm_disk_id`, `nic_ext_id`, `mac_address`, and `ip_address`. The separate
`vm_ext_id` addresses Prism; the broker verifies the live Prism `biosUuid`
against the guest identity instead of assuming those identifiers are equal.
These values are inventory facts only.
In particular, `vtpm_disk_id` is not a TPM public key and does not prove
possession. The broker re-reads all five claims from Prism and requires the
request's real source address before accepting the NGT proof, TPM credential
activation, and nonce-bound quote. The enrollment network must prevent source
IP and MAC spoofing; otherwise the broker must remain unavailable.

All configurable attributes are replace-only. Destroying or replacing the
resource revokes the registration while retaining the server-side audit record.
Production use requires provider JWK administrator authentication. For every
request, the provider creates a fresh Step CA administrator JWT for the Step CA
admin-validation endpoint; the enrollment service delegates validation back to
Step CA. `machine_enrollment_token` exists only for local development.

Pending registrations are short-lived. Terraform preserves an expired or
revoked registration in state and emits a warning; it never silently creates a
new identity. After reviewing the cause, an administrator can recover with
`terraform apply -replace=stepca_machine_enrollment.vm`.

## Arguments

- `attestor_type` — platform attestor type, initially `nutanix-vtpm`.
- `attestor_identity` — stable inventory identity within that type.
- `attestor_claims` — expected string claims checked during attestation.
- `machine_identity` — requested machine identity subject.
- `ssh_principals` — requested SSH host principals, subject to server policy.

## Read-only attributes

- `id` — enrollment registration identifier.
- `status` — lifecycle status returned by the enrollment service.
