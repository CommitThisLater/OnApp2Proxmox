### OnApp to Proxmox Migrations

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

## Linux Swap space
- It's important to note that we must maintain the current setup with swap disks as below,
- Do not migrate the swap disk as a secondary disk for Linux VMs, swap will be added to the primary disk if a --swapsize is specified during the migration.
- If the source VM has a swap disk in OnApp, you must migrate it by specifying --swapsize on the migration command.
- If the source VM does not have a swap disk, just omit the --swapsize option.
- Altering the swap status will break the logic and cause issues with the migrated VM.

## Migrating disks 
- You must migrate the primary disk and all other secondary disks.
- Specify disks in the order they are listed in OnApp, primary first, then secondary disks in order.

## Vm specifications
- CPU cores will default to 4 if not specified during the migration.
- RAM will default to 4096MB if not specified during the migration.
- To specify use --cores and --memory.

## Migrating networks
- You must specify network interfaces in the correct order with the primary interface first.
- Use the same virtual MAC address as listed in OnApp to avoid any issues after the migration.
- List network interfaces as follows, --nic <bridge,macaddr,mtu> <bridge,macaddr,mtu>

## Supported Operating Systems
- **Linux:** The script applies the above customisations automatically.
- **Windows:** No additional modifications should be required in most cases.
- **Other OS Types:** Customisation may be required to fit specific use cases. 

## Requirements
- The **source VM must be shut down** before running this script.
- The script **does not shut down** the source VM automatically.
- The source OnApp VMs must have **virtio** support, this will be true in most cases.
  - If using non-virtio, modifications to the controller and disk type configs under the hardware panel of the VM may be required before booting the VM in Proxmox.
- The script requires the **MAC address** of the network interface to maintain the same virtual MAC and avoid network issues inside the VM.
- This script assumes **OnApp Integrated Storage**.
  - It can be modified to support **local or SAN storage using LVM**. We will probably implement this but don't have access to an OnApp environment with LVM datastores.
- The script must be run from an **OnApp host or backup server** to access the OnApp storage layer.
- Ensure **sufficient disk space** is available on both ends to temporarily store the disk images.
- The script **removes the copied disk images on the source side** after migration is complete but does **not** modify the source VM at all so rollback is simple.
- Disk images should be manually removed from the Proxmox side after a successful migration.
- Running the script from the **backup server on the OnApp side** is recommended.

## Added in last commit
We have now added support for specifying NICs as part of the migration process using --nic <bridge,macaddr,mtu>
As mentioned above we ask for the MAC address as this keeps the same virtual MAC and avoids any issues, particularly in Windows. 
To specify multiple interfaces do --mac <bridge,macaddr,mtu> <bridge,macaddr,mtu>
Make sure you specify the primary interface first!

Specifying --swapsize is now optional as not all VMs in OnApp will have swap, as mentioned above, only specify --swapsize if the source VM has a swap disk.
If you specify swapsize and the source VM doesn't have swap it will break the logic in the script and cause the migration to fail. 

## To-Do
- Add support for LVM datastores for OnApp clouds using local or SAN storage. 
  
## Example usage
Linux: sh onapp2proxmox.sh --swap-size 1024 --host 192.168.1.1 --cores 8 --memory 8192 --vmname onapp-vm-01 -p l7a3u8sngmrtc0:Ceph_Storage -s 4u32reaicnk075:Ceph_Storage --os linux --nics vmbr0,00:16:3e:25:dc:64,1500 vmbr1,00:16:3e:25:dc:62,1500
Windows: sh onapp2proxmox.sh --host 192.168.1.1 --cores 8 --memory 8192 --vmname onapp-vm-02 -p l7a3u8sngmrtc0:Ceph_Storage -s 4u32reaicnk075:Ceph_Storage --os windows --nics vmbr0,00:16:3e:25:dc:64,1500 vmbr1,00:16:3e:25:dc:62,1500