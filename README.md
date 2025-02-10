# OnApp to Proxmox Migrations

Automation for migrating OnApp VMs to Proxmox VE.

## Overview
This script automates the migration of virtual machines from OnApp to Proxmox, ensuring minimal manual intervention while preserving VM configurations as much as possible.

## Features
The script will:
1. Take a copy of the specified disk images using `dd`.
2. Remove the swap space, which was previously on a separate physical disk (Linux).
3. Modify the disk images to add swap space under `/swapfile` (Linux).
4. Install the `qemu-guest-agent` package (Linux).
5. Create a new VM on the Proxmox host.
6. Transfer and import the disk images.

Do not migrate the swap disk for Linux VMs, swap will be added to the primary disk.
You must migrate the primary disk and all other secondary disks.

## Supported Operating Systems
- **Linux:** The script applies the above customizations automatically.
- **Windows:** No additional modifications should be required in most cases.
- **Other OS Types:** Customization may be required to fit specific use cases. 
  - This script will be modified further in future to support **pfSense** as it's the valid use case for "other" on this project.

## Requirements
- The **source VM must be shut down** before running this script.
- The script **does not shut down** the source VM automatically.
- The source OnApp VMs must have **virtio** support, this will be true in most cases.
  - If using non-virtio, modifications to the controller and disk type configs may be required before booting the VM in Proxmox.
- The script requires the **MAC address** of the network interface to maintain the same virtual MAC and avoid network issues inside the VM.
- This script assumes **OnApp Integrated Storage**.
  - It can be modified to support **local or SAN storage using LVM**. We will probably implement this but don't have access to an OnApp environment with LVM datastores.
- The script must be run from an **OnApp host or backup server** to access the OnApp storage layer.
- Ensure **sufficient disk space** is available on both ends to temporarily store the disk images.
- The script **removes the copied disk images on the source side** after migration is complete but does **not** modify the source VM at all so rollback is simple.
- Disk images should be manually removed from the Proxmox side after a successful migration.
- Running the script from the **backup server on the OnApp side** is recommended.

Please review the comments at the top of the script as more details will be added there as the development continues. 

## To-Do
- Allow specifying destination VM specifications (RAM, CPU cores, etc.).
- Ability to select destination network bridge in Proxmox for more complex setups (we will implement this).
  Support for multiple network interfaces as a result of the above.
  
# Example usage:
sh onapp2proxmox.sh --swap-size 1024 --host 192.168.1.2 --mac 00:16:3d:26:dc:64 --vmname vm-name -p l7a3u8sngmrtc0:Ceph_Master -s 4u32reaicnk075:Ceph_Master --os linux
