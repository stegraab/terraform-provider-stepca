terraform {
  required_providers {
    nutanix = {
      source = "nutanix/nutanix"
    }
    stepca = {
      source = "stegraab/stepca"
    }
  }
}

resource "stepca_machine_enrollment" "vm" {
  attestor_type     = "nutanix-vtpm"
  attestor_identity = nutanix_virtual_machine_v2.vm.ext_id
  attestor_claims = {
    generation_uuid = nutanix_virtual_machine_v2.vm.generation_uuid
    vtpm_disk_id    = nutanix_virtual_machine_v2.vm.vtpm_disk_id
  }

  machine_identity = "host/example.internal"
  ssh_principals   = ["example", "example.internal"]
}
