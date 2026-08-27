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
    nic_ext_id      = nutanix_virtual_machine_v2.vm.nics[0].ext_id
    mac_address     = nutanix_virtual_machine_v2.vm.nics[0].nic_backing_info[0].virtual_ethernet_nic[0].mac_address
    ip_address      = nutanix_virtual_machine_v2.vm.nics[0].nic_network_info[0].virtual_ethernet_nic_network_info[0].ipv4_config[0].ip_address[0].value
  }

  machine_identity = "host/example.internal"
  ssh_principals   = ["example", "example.internal"]
}
