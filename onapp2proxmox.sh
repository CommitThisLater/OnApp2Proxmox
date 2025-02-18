#!/bin/bash
#
# OnApp to Proxmox migrations
#
# The script will...
#
# 1, Take a copy of the specified disk images using dd.
# 2, Remove the swap space which was previously on a separate physical disk (linux).
# 3, Modify the disk images to add swap space under /swapfile (linux).
# 4, Install the qemu-guest-agent package (linux).
# 5, Create a new VM on the Proxmox host.
# 6, Transfer and import the disk images.
#
# We support Linux, Windows, and other OS types.
# Linux customisations are listed above, Windows should not require any additional customisations to boot in Proxmox in most cases
# Other OS types will require customisations to fit your use case.
#
# The source VM must be shutdown before running this script.
# The script will not shutdown the source VM.
#
# Do not attempt to move the swap disk for Linux VMs, this script will create the swap space on the primary disk.
# You must move the primary disk and all secondary disks as part of the migration.
#
# We assume all source OnApp VMs are running with virtio support, modifications to the controller and disk type may be required for non-virtio VMs.
#
# It's a good idea to keep the same virtual mac address for the network interface to avoid network issues 
# The script therefore requires the mac address to be specified.
#
# This script assumes you are running OnApp Integrated Storage.
# It can be easily modified to support local or SAN storage which uses LVM.
#
# It needs to be run from either the OnApp hosts or backup servers to gain access to the OnApp storage layer.
# Enough disk space should be available to temporarily store the disk images on both ends.
# The script will remove the disk images on the source side after the VM has been created on Proxmox, we do not touch the source VM.
# The disk images should be removed from the Proxmox side after a successful migration.
# Running the script from the backup server on the OnApp side is a good choice.
#
# - ToDo: Specify destination VM specifications (RAM, CPU Cores, etc).
#         Ability to select destination network bridge in Proxmox for more complex setups (we will implement this).
#         Support for multiple network interfaces as a result of the above.
#         Support for package installations on Windows (qemu-guest-agent).
#         Add LVM and local storage datastore types, currently we only support OnApp Integrated Storage (need an OnApp LVM test environemnt to do this).
#
# Example usage with two secondary disks:
# sh convert.sh --swap-size 1024 --host 192.168.117.213 --mac 00:16:3e:25:dc:65 --vmname vm-name \
#  -p l7a3u8sngmrtc0:Ceph_Master -s 4u32reaicnk075:Ceph_Master -s fj8dndji9ed6g2:Ceph_Master \
#   --os linux
###

# Check if the script is running in bash
if [ -z "$BASH" ]; then
  exec /bin/bash "$0" "$@"
fi

# Exit on error
set -euo pipefail

###### Configurations for your environment ######
#
# Array of Proxmox host IPs - Add all host IP from your cluster
# An ssh key is required to transfer and deploy the images
hosts=("192.168.1.10" "192.168.1.20" "192.168.1.30")
#
# Where to upload the disk images on the Proxmox side (no trailing slash)
# We are using /dev here as it has the most space, /root would be a better option
uploadDir="/dev"
# The SSH user for accessing Proxmox hosts, in most cases should be root
sshUser="root"
#################################################

disksOnline=false
# Cleanup function / trap exit
cleanup() {
    echo "Cleaning up resources... (DO NOT INTERRUPT!)"
    rm -f .lock

    if [[ "$disksOnline" == true ]]; then
        onappstore offline uuid=$primaryDisk
        rm -f ${primaryDisk}.img

        if [[ ${#secondaryDisks[@]} -gt 0 ]]; then
            for i in "${!secondaryDisks[@]}"; do
                onappstore offline uuid=${secondaryDisks[$i]}
                rm -f ${secondaryDisks[$i]}.img
            done
        fi
    fi
}
trap cleanup EXIT

# Check running
if [[ -e ".lock" ]]; then
    echo "Script is already running (.lock exists)"
    exit 1
fi
touch .lock

# Usage
usage() {
    echo "Usage: $0 --swap-size <swap_SizeMB> [[ --host <hostIP> | --random-host ]] --vmname <vmName> 
            --nic <bridge,macaddr,mtu> <bridge,macaddr,mtu> ... 
             -p <primaryDisk>:<datastore> -s <secondaryDisk1>:<datastore> <secondaryDisk>:<datastore> ... 
              --os <linux|windows|other>"
    echo
    echo "Arguments:"
    echo "  --swap-size <swapSizeMB>                                            Size of the swap space in MB (e.g., 1024)"
    echo "  --host <hostIP>                                                     IP address of the Proxmox host (e.g., 192.168.1.100)"
    echo "  --random-host                                                       Select a random Proxmox host from the predefined list"
    echo "  --vmname <vmName>                                                   Name of the VM (only lowercase letters, numbers, and '-' allowed)"
    echo "  --nics <bridge,macaddr,mtu> ...                                     Network interfaces for the VM (primary NIC is mandatory, for multiple NICs specify with --nics <bridge,macaddr,mtu> <bridge,macaddr,mtu> putting the primary first)"
    echo "  -p <primaryDisk>:<datastore>                                        Path to the primary disk and associated proxmox datastore"
    echo "  -s <secondaryDisk1>:<datastore> <secondaryDisk2>:<datastore> ...    Paths to secondary disks and associated datastores(optional)"
    echo "  --os <linux|windows|other>                                          Specify the OS type (mandatory)"
    echo
    echo "Example: $0 --swap-size 1024 --random-host --vmname my-vm-01 --nics <vmbr0,00:1a:2b:3c:4d:5e,1500> -p pc2qwegju5f740:DataStoreSSD -s hk8udjdi85eg7n:DataStoreSSD k8jhd6wujkb79u:DataStoreHDD --os linux"
    exit 1
}

# We need root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root or with sudo."
    usage
fi

# Validate inbound arguments
if [ $# -lt 7 ]; then
    echo "Error: At least 7 arguments are required."
    usage
fi

# Inbound vars
swapSize=""
host=""
randomHost=false
vmName=""
osType=""
primaryDisk=""
primaryDatastore=""
secondaryDisks=()
secondaryDatastores=()
nics=()

# Parse the command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --swap-size)
            swapSize=$2
            shift 2
            ;;
        --host)
            host=$2
            shift 2
            ;;
        --random-host)
            randomHost=true
            shift 1
            ;;
        --vmname)
            vmName=$2
            shift 2
            ;;
        -p) 
            if [[ "$2" =~ : ]]; then
                primaryDisk=$(echo $2 | cut -d':' -f1)
                primaryDatastore=$(echo $2 | cut -d':' -f2)
            else
                echo "Error: Primary disk and datastore must be in the format 'diskid:datastore'."
                usage
                exit 1
            fi
            shift 2
            ;;
        -s) 
            if [[ "$2" =~ : ]]; then
                secondaryDisks+=($(echo $2 | cut -d':' -f1))
                secondaryDatastores+=($(echo $2 | cut -d':' -f2))
            else
                echo "Error: Secondary disk and datastore must be in the format 'diskid:datastore'."
                usage
                exit 1
            fi
            shift 2
            ;;
        --nics)
            nicsInput=$2
            IFS=' ' read -r -a nics <<< "$(echo "$nicsInput" | tr ',' ' ')"
            shift 2
            ;;
        --os)
            osType=$2
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

# Ensure that only one of --host or --random-host is used
if [[ -n "$host" && "$randomHost" == true ]]; then
    echo "Error: You cannot specify both --host and --random-host."
    usage
elif [[ -z "$host" && "$randomHost" == false ]]; then
    echo "Error: You must specify either --host or --random-host."
    usage
fi

# Select a random host if --random-host is used
if [[ "$randomHost" == true ]]; then
    host=${hosts[$RANDOM % ${#hosts[@]}]}
    echo "Selected random Proxmox host: $host"
fi

# Validate required parameters
if [ -z "$swapSize" ] || [ -z "$host" ] || [ -z "$mac" ] || [ -z "$vmName" ] || [ -z "$osType" ]; then
    echo "Error: Missing required arguments."
    usage
fi

# Validate the OS type
if [[ "$osType" != "linux" && "$osType" != "windows" && "$osType" != "other" ]]; then
    echo "Error: Invalid OS type. Allowed values are linux, windows, or other."
    usage
fi

# Validate the swap size
if ! [[ "$swapSize" =~ ^[0-9]+$ ]] || [ "$swapSize" -le 0 ]; then
    echo "Error: Swap size must be a positive integer specified in MB."
    usage
fi

# Validate the host IP address
if ! [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && ! [[ "$host" =~ ^[a-fA-F0-9:]+$ ]]; then
    echo "Error: host must be a valid IP address (IPv4 or IPv6)."
    usage
fi

# Validate the vmName
if ! [[ "$vmName" =~ ^[a-z0-9-]+$ ]]; then
    echo "Error: vmName must only contain lowercase letters, numbers, and hyphens (-)."
    usage
fi

# Validate primaryDisk and primaryDatastore
if [[ -z "$primaryDisk" || -z "$primaryDatastore" ]]; then
    echo "Error: Both primaryDisk and primaryDatastore must be specified."
    usage
    exit 1
fi

# Validate primaryDisk format
if [[ ! "$primaryDisk" =~ ^[a-zA-Z0-9]+$ ]]; then
    echo "Error: Invalid primaryDisk format: $primaryDisk. Must be alphanumeric."
    usage
    exit 1
fi

# Validate primaryDatastore format
if [[ ! "$primaryDatastore" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Error: Invalid primaryDatastore format: $primaryDatastore. Must be alphanumeric, '_', or '-'."
    usage
    exit 1
fi

# Validate secondary disks and datastores
if [[ ${#secondaryDisks[@]} -gt 0 && ${#secondaryDisks[@]} -ne ${#secondaryDatastores[@]} ]]; then 
    echo "Error: Number of secondary disks does not match number of secondary datastores." 
    usage
    exit 1
fi

# Validate NIC format
for nic in "${nics[@]}"; do
    if ! [[ "$nic" =~ ^[a-zA-Z0-9_-]+,[0-9a-fA-F:]+,[0-9]+$ ]]; then
        echo "Error: Invalid NIC format. Use bridge,macaddr,mtu."
        usage
        exit 1
    fi
done

check_ssh_access() {
    local user="$1"
    local ip="$2"

    echo "Checking SSH access for ${user}@${ip}..."

    if ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no "${user}@${ip}" exit 2>/dev/null; then
        echo "SSH access is available without a password for ${user}@${ip}"
        return 0
    else
        echo "SSH access failed for ${user}@${ip} - Make sure SSH is available with RSA key authentication."
        exit 1
    fi
}

ssh_exec() {
    ssh -o StrictHostKeyChecking=no ${sshUser}@"$1" "$2"
}

check_datastore() {
    local datastore=$1
    local pveOutput=$(ssh -o StrictHostKeyChecking=no ${sshUser}@${host} "pvesm status")

    if echo "$pveOutput" | awk '{print $1}' | grep -Fxq "$datastore"; then
        status=$(echo "$pveOutput" | awk -v ds="$datastore" '$1 == ds {print $3}')
        if [ "$status" == "active" ]; then
            echo "Datastore '$datastore' exists and is active."
        else
            echo "Error: Datastore '$datastore' exists but is NOT active."
            exit 1
        fi
    else
        echo "Error: Datastore '$datastore' does not exist."
        exit 1
    fi
}

create_disk_image() {
    local disk=$1

    # Get frontend UUID
    frontend=$(onappstore getid | awk '{print $2}' | cut -d= -f2)
    if [ $? -ne 0 ]; then
        echo "Error: Failed to get frontend ID."
        return 1
    fi

    # Bring frontend online
    onappstore online uuid=$disk frontend_uuid=$frontend
    if [ $? -ne 0 ]; then
        echo "Error: Failed to bring the frontend online."
        return 1
    fi
    disksOnline=true

    # Create disk image
    dd if=/dev/mapper/$disk of=${disk}.img bs=1M
    if [ $? -ne 0 ]; then
        echo "Error: Disk image creation failed."
        return 1
    fi

    onappstore offline uuid=$disk
    disksOnline=false

    echo "Disk image creation for $disk successful."
    return 0
}

# Make sure we can SSH to the Proxmox host
check_ssh_access "${sshUser}" "$host"

# Make sure the datastores exist and are active in Proxmox
check_datastore "$primaryDatastore"

for ds in "${secondaryDatastores[@]}"; do
    check_datastore "$ds"
done

# Get the next VM ID from Proxmox on the $host server
vmid=$(ssh ${sshUser}@${host} "pvesh get /cluster/nextid")
if [ -z "$vmid" ]; then
    echo "Error: Unable to get a valid vmid from Proxmox."
    exit 1
fi

# Remove existing local disk images
if [[ -e "${primaryDisk}.img" ]]; then
    rm ${primaryDisk}.img
fi
create_disk_image "$primaryDisk"

# Secondary disks if any
if [ ${#secondaryDisks[@]} -gt 0 ]; then
    for i in "${!secondaryDisks[@]}"; do
        if [[ -e "${secondaryDisks[$i]}.img" ]]; then
            rm ${secondaryDisks[$i]}.img
        fi
        create_disk_image ${secondaryDisks[$i]}
    done
fi

# Linux specific customisations
if [[ "$osType" == "linux" ]]; then

    # Resize the image to allow for swap
    qemu-img resize -f raw "${primaryDisk}.img" +${swapSize}M
    virt-customize -a "${primaryDisk}.img" --run-command 'growpart /dev/sda 1 && resize2fs /dev/sda1'

    # Create a swapfile
    virt-customize -a "${primaryDisk}.img" \
    --run-command "dd if=/dev/zero of=/swapfile bs=1M count=$swapSize" \
    --run-command "chmod 600 /swapfile" \
    --run-command "mkswap /swapfile"

    # View fstab before changes
    virt-cat --format=raw -a "${primaryDisk}.img" /etc/fstab

    # Update /etc/fstab to add the new swapfile
    virt-customize -a "${primaryDisk}.img" \
    --run-command "sed -i '/swap/d' /etc/fstab" \
    --run-command "echo '/swapfile none swap sw 0 0' >> /etc/fstab"

    # A messy restructure of the fstab for missing swap
    virt-customize -a "${primaryDisk}.img" --run-command "
    awk '{
        if (\$1 == \"/dev/vdk\") \$1 = \"/dev/vdj\";
        else if (\$1 == \"/dev/vdj1\") \$1 = \"/dev/vdi1\";
        else if (\$1 == \"/dev/vdi1\") \$1 = \"/dev/vdh1\";
        else if (\$1 == \"/dev/vdh1\") \$1 = \"/dev/vdg1\";
        else if (\$1 == \"/dev/vdg1\") \$1 = \"/dev/vdf1\";
        else if (\$1 == \"/dev/vdf1\") \$1 = \"/dev/vde1\";
        else if (\$1 == \"/dev/vde1\") \$1 = \"/dev/vdd1\";
        else if (\$1 == \"/dev/vdd1\") \$1 = \"/dev/vdc1\";
        else if (\$1 == \"/dev/vdc1\") \$1 = \"/dev/vdb1\";
        else if (\$1 == \"/dev/vdb1\") \$1 = \"/dev/vda1\";
        else if (\$1 == \"/dev/vdg\") \$1 = \"/dev/vdf\";
        else if (\$1 == \"/dev/vdf\") \$1 = \"/dev/vde\";
        else if (\$1 == \"/dev/vde\") \$1 = \"/dev/vdd\";
        else if (\$1 == \"/dev/vdd\") \$1 = \"/dev/vdc\";
        else if (\$1 == \"/dev/vdc\") \$1 = \"/dev/vdb\";
        else if (\$1 == \"/dev/vdb\") \$1 = \"/dev/vda\";
        print;
    }' /etc/fstab > temp_file && mv temp_file /etc/fstab
    "

    # Build grub
    virt-customize -a "${primaryDisk}.img" \
    --run-command 'echo "(hd0) /dev/sda" > /boot/grub/device.map' \
    --run-command 'grub-install /dev/sda' --run-command 'update-grub' \
    --run-command "find /boot/grub -type f -exec sed -i 's|/dev/sda|/dev/vda|g' {} \;"

    # View fstab after changes
    virt-cat --format=raw -a "${primaryDisk}.img" /etc/fstab

    # Add the qemu guest agent, requires networking at first boot
    virt-customize -a "${primaryDisk}.img" \
    --firstboot-install qemu-guest-agent \
    --firstboot-command "systemctl enable --now qemu-guest-agent"

fi

if [[ "$osType" == "windows" ]]; then
    :
    # Windows specific customisations
    # Currently nothing is required here for a standard Windows VM
fi

if [[ "$osType" == "other" ]]; then
    :
    # Other OS specific customisations
    # In this instance we assume other is for pfSense as that was relevant to this project at the time of development.
    # This section will generally cover unknown OS types and as such, should be customised to fit your use case.
fi

# Prepare network arguments for Proxmox
net_args=()
for nic in "${nics[@]}"; do
    bridge=$(echo $nic | cut -d',' -f1)
    macaddr=$(echo $nic | cut -d',' -f2)
    mtu=$(echo $nic | cut -d',' -f3)
    net_args+=("--net${#net_args[@]} virtio,bridge=${bridge},macaddr=${macaddr},mtu=${mtu},firewall=1")
done

# Transfer and build the VM on Proxmox
scp ${primaryDisk}.img ${sshUser}@${host}:${uploadDir}/
ssh_exec "$host" "qm create $vmid \
  --name $vmName \
  --virtio0 ${primaryDatastore}:0,discard=on,import-from=${uploadDir}/${primaryDisk}.img \
  --agent enabled=1,type=virtio,freeze-fs-on-backup=1 \
  --ostype l26 \
  --cores 4 \
  --memory 4096 \
  ${net_args[@]} \
  --onboot 1 \
  --scsihw virtio-scsi-pci"

x=1
# Transfer and build the secondary disks (if any)
for i in "${!secondaryDisks[@]}"; do
    scp "${secondaryDisks[$i]}.img" ${sshUser}@${host}:${uploadDir}/
    ssh_exec "$host" "qm importdisk $vmid ${uploadDir}/${secondaryDisks[$i]}.img ${secondaryDatastores[$i]}"
    ssh_exec "$host" "qm rescan --vmid $vmid"
    ssh_exec "$host" "qm set $vmid --virtio${x} ${secondaryDatastores[$i]}:vm-${vmid}-disk-${x},discard=on"
    ((x++))
done
