#!/bin/bash
#
# - OnApp to Proxmox migrations
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
#         Support for package installations on RHEL and Debian based Linux distros.
#         Support for package installations on Windows (qemu-guest-agent).
#         Add LVM and local storage datastore types, currently we only support OnApp Integrated Storage (need an OnApp LVM test environemnt to do this).
#
# Example usage:
# sh convert.sh --swap-size 1024 --host 192.168.117.213 --mac 00:16:3e:25:dc:65 \
#  --vmname vm-name -p l7a3u8sngmrtc0:Ceph_Master -s 4u32reaicnk075:Ceph_Master \
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
HOSTS=("192.168.1.10" "192.168.1.20" "192.168.1.30")
#
# Where to upload the disk images on the Proxmox side (no trailing slash)
# We are using /dev here as it has the most space, /root would be a better option
UPLOAD_DIR="/dev"
#################################################

disks_online=false
# Cleanup function / trap exit
cleanup() {
    echo "Cleaning up resources... (DO NOT INTERRUPT!)"
    rm -f .lock

    if [[ "$disks_online" == true ]]; then
        onappstore offline uuid=$PRIMARY_DISK
        rm -f ${PRIMARY_DISK}.img

        if [[ ${#SECONDARY_DISKS[@]} -gt 0 ]]; then
            for i in "${!SECONDARY_DISKS[@]}"; do
                onappstore offline uuid=${SECONDARY_DISKS[$i]}
                rm -f ${SECONDARY_DISKS[$i]}.img
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
    echo "Usage: $0 --swap-size <SWAP_SIZE_MB> [[ --host <HOST_IP> | --random-host ]] --mac <MAC_ADDRESS> 
       --vmname <VMNAME> -p <PRIMARY_DISK>:<DATASTORE> 
         -s <SECONDARY_DISK1>:<DATASTORE> <SECONDARY_DISK2>:<DATASTORE> ... 
          --os <linux|windows|other>"
    echo
    echo "Arguments:"
    echo "  --swap-size <SWAP_SIZE_MB>                                          Size of the swap space in MB (e.g., 1024)"
    echo "  --host <HOST_IP>                                                    IP address of the Proxmox host (e.g., 192.168.1.100)"
    echo "  --random-host                                                       Select a random Proxmox host from the predefined list"
    echo "  --mac <MAC_ADDRESS>                                                 MAC address for the VM network interface (e.g., 00:1a:2b:3c:4d:5e)"
    echo "  --vmname <VMNAME>                                                   Name of the VM (only lowercase letters, numbers, and '-' allowed)"
    echo "  -p <PRIMARY_DISK>:<DATASTORE>                                       Path to the primary disk and associated proxmox datastore"
    echo "  -s <SECONDARY_DISK1>:<DATASTORE> <SECONDARY_DISK2>:<DATASTORE> ...  Paths to secondary disks and associated datastores(optional)"
    echo "  --os <linux|windows|other>                                          Specify the OS type (mandatory)"
    echo
    echo "Example: $0 --swap-size 1024 --random-host --mac 00:1a:2b:3c:4d:5e --vmname vm-name-01 -p pc2qwegju5f740:DataStoreSSD -s hk8udjdi85eg7n:DataStoreSSD k8jhd6wujkb79u:DataStoreHDD --os linux"
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
SWAP_SIZE=""
HOST=""
RANDOM_HOST=false
MAC=""
VMNAME=""
OS_TYPE=""
PRIMARY_DISK=""
PRIMARY_DATASTORE=""
SECONDARY_DISKS=()
SECONDARY_DATASTORES=()

# Parse the command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --swap-size)
            SWAP_SIZE=$2
            shift 2
            ;;
        --host)
            HOST=$2
            shift 2
            ;;
        --random-host)
            RANDOM_HOST=true
            shift 1
            ;;
        --mac)
            MAC=$2
            shift 2
            ;;
        --vmname)
            VMNAME=$2
            shift 2
            ;;
        -p) 
            PRIMARY_DISK=$(echo $2 | cut -d':' -f1)
            PRIMARY_DATASTORE=$(echo $2 | cut -d':' -f2)
            shift 2
            ;;
        -s) 
            SECONDARY_DISKS+=($(echo $2 | cut -d':' -f1))
            SECONDARY_DATASTORES+=($(echo $2 | cut -d':' -f2))
            shift 2
            ;;
        --os)
            OS_TYPE=$2
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

# Ensure that only one of --host or --random-host is used
if [[ -n "$HOST" && "$RANDOM_HOST" == true ]]; then
    echo "Error: You cannot specify both --host and --random-host."
    usage
elif [[ -z "$HOST" && "$RANDOM_HOST" == false ]]; then
    echo "Error: You must specify either --host or --random-host."
    usage
fi

# Select a random host if --random-host is used
if [[ "$RANDOM_HOST" == true ]]; then
    HOST=${HOSTS[$RANDOM % ${#HOSTS[@]}]}
    echo "Selected random Proxmox host: $HOST"
fi

# Validate required parameters
if [ -z "$SWAP_SIZE" ] || [ -z "$HOST" ] || [ -z "$MAC" ] || [ -z "$VMNAME" ] || [ -z "$OS_TYPE" ]; then
    echo "Error: Missing required arguments."
    usage
fi

# Validate the OS type
if [[ "$OS_TYPE" != "linux" && "$OS_TYPE" != "windows" && "$OS_TYPE" != "other" ]]; then
    echo "Error: Invalid OS type. Allowed values are linux, windows, or other."
    usage
fi

# Validate the swap size
if ! [[ "$SWAP_SIZE" =~ ^[0-9]+$ ]] || [ "$SWAP_SIZE" -le 0 ]; then
    echo "Error: Swap size must be a positive integer specified in MB."
    usage
fi

# Validate the HOST IP address
if ! [[ "$HOST" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && ! [[ "$HOST" =~ ^[a-fA-F0-9:]+$ ]]; then
    echo "Error: HOST must be a valid IP address (IPv4 or IPv6)."
    usage
fi

# Validate the MAC address
if ! [[ "$MAC" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
    echo "Error: MAC address must be in the format XX:XX:XX:XX:XX:XX."
    usage
fi

# Validate the VMNAME
if ! [[ "$VMNAME" =~ ^[a-z0-9-]+$ ]]; then
    echo "Error: VMNAME must only contain lowercase letters, numbers, and hyphens (-)."
    usage
fi

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

check_datastore() {
    local DATASTORE=$1
    local PVE_OUTPUT=$(ssh -o StrictHostKeyChecking=no root@${HOST} "pvesm status")

    if echo "$PVE_OUTPUT" | awk '{print $1}' | grep -Fxq "$DATASTORE"; then
        STATUS=$(echo "$PVE_OUTPUT" | awk -v ds="$DATASTORE" '$1 == ds {print $3}')
        if [ "$STATUS" == "active" ]; then
            echo "Datastore '$DATASTORE' exists and is active."
        else
            echo "Error: Datastore '$DATASTORE' exists but is NOT active."
            exit 1
        fi
    else
        echo "Error: Datastore '$DATASTORE' does not exist."
        exit 1
    fi
}

create_disk_image() {
    local DISK=$1

    # Get frontend UUID
    FRONTEND=$(onappstore getid | awk '{print $2}' | cut -d= -f2)
    if [ $? -ne 0 ]; then
        echo "Error: Failed to get frontend ID."
        return 1
    fi

    # Bring frontend online
    onappstore online uuid=$DISK frontend_uuid=$FRONTEND
    if [ $? -ne 0 ]; then
        echo "Error: Failed to bring the frontend online."
        return 1
    fi
    disks_online=true

    # Create disk image
    dd if=/dev/mapper/$DISK of=${DISK}.img bs=1M
    if [ $? -ne 0 ]; then
        echo "Error: Disk image creation failed."
        return 1
    fi

    onappstore offline uuid=$DISK
    disks_online=false

    echo "Disk image creation for $DISK successful."
    return 0
}

# Make sure we can SSH to the Proxmox host
check_ssh_access "root" "$HOST"

# Make sure the datastores exist and are active
check_datastore "$PRIMARY_DATASTORE"

for DS in "${SECONDARY_DATASTORES[@]}"; do
    check_datastore "$DS"
done

# Get the next VM ID from Proxmox on the $HOST server
VMID=$(ssh root@${HOST} "pvesh get /cluster/nextid")
if [ -z "$VMID" ]; then
    echo "Error: Unable to get a valid VMID from Proxmox."
    exit 1
fi

# Remove existing local disk images
if [[ -e "${PRIMARY_DISK}.img" ]]; then
    rm ${PRIMARY_DISK}.img
fi
create_disk_image "$PRIMARY_DISK"

# Secondary disks if any
if [ ${#SECONDARY_DISKS[@]} -gt 0 ]; then
    for i in "${!SECONDARY_DISKS[@]}"; do
        if [[ -e "${SECONDARY_DISKS[$i]}.img" ]]; then
            rm ${SECONDARY_DISKS[$i]}.img
        fi
        create_disk_image ${SECONDARY_DISKS[$i]}
    done
fi

# Linux specific customisations
if [[ "$OS_TYPE" == "linux" ]]; then

    # Resize the image to allow for swap
    qemu-img resize -f raw "${PRIMARY_DISK}.img" +${SWAP_SIZE}M
    virt-customize -a "${PRIMARY_DISK}.img" --run-command 'growpart /dev/sda 1 && resize2fs /dev/sda1'

    # Create a swapfile
    virt-customize -a "${PRIMARY_DISK}.img" \
    --run-command "dd if=/dev/zero of=/swapfile bs=1M count=$SWAP_SIZE" \
    --run-command "chmod 600 /swapfile" \
    --run-command "mkswap /swapfile"

    # View fstab before changes
    virt-cat --format=raw -a "${PRIMARY_DISK}.img" /etc/fstab

    # Update /etc/fstab to add the new swapfile
    virt-customize -a "${PRIMARY_DISK}.img" \
    --run-command "sed -i '/swap/d' /etc/fstab" \
    --run-command "echo '/swapfile none swap sw 0 0' >> /etc/fstab"

    # A messy restructure of the fstab for missing swap
    virt-customize -a "${PRIMARY_DISK}.img" --run-command "
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
    virt-customize -a "${PRIMARY_DISK}.img" \
    --run-command 'echo "(hd0) /dev/sda" > /boot/grub/device.map' \
    --run-command 'grub-install /dev/sda' --run-command 'update-grub' \
    --run-command "find /boot/grub -type f -exec sed -i 's|/dev/sda|/dev/vda|g' {} \;"

    # View fstab after changes
    virt-cat --format=raw -a "${PRIMARY_DISK}.img" /etc/fstab

    # Add the guest agent
    virt-customize -a "${PRIMARY_DISK}.img" --run-command '
        if [[ -f /etc/os-release ]]; then
            . /etc/os-release
        elif [[ -f /etc/redhat-release ]]; then
            ID="rhel"
        fi

        case "$ID" in
            debian|ubuntu)
                apt-get update && apt-get install -y qemu-guest-agent
                ;;
            centos|rhel|rocky|almalinux)
                if command -v dnf >/dev/null 2>&1; then
                    dnf install -y qemu-guest-agent
                else
                    yum install -y qemu-guest-agent
                fi
                ;;
            *)
                exit 0
                ;;
        esac
        systemctl enable qemu-guest-agent
    '
fi

if [[ "$OS_TYPE" == "windows" ]]; then
    :
    # Windows specific customisations
    # Currently nothing is required here for a standard Windows VM
fi

if [[ "$OS_TYPE" == "other" ]]; then
    :
    # Other OS specific customisations
    # In this instance we assume other is for pfSense as that was relevant to this project at the time of development.
    # This section will generally cover unknown OS types and as such, should be customised to fit your use case.
fi

# Transfer and build the VM on Proxmox
scp ${PRIMARY_DISK}.img root@${HOST}:${UPLOAD_DIR}/
ssh -o StrictHostKeyChecking=no root@${HOST} "qm create $VMID \
  --name $VMNAME \
  --virtio0 ${PRIMARY_DATASTORE}:0,discard=on,import-from=${UPLOAD_DIR}/${PRIMARY_DISK}.img \
  --agent enabled=1,type=virtio,freeze-fs-on-backup=1 \
  --ostype l26 \
  --cores 4 \
  --memory 4096 \
  --net0 virtio,bridge=vmbr0,macaddr=${MAC} \
  --onboot 1 \
  --scsihw virtio-scsi-pci"

x=1
# Transfer and build the secondary disks (if any)
for i in "${!SECONDARY_DISKS[@]}"; do
    scp "${SECONDARY_DISKS[$i]}.img" root@${HOST}:${UPLOAD_DIR}/
    ssh -o StrictHostKeyChecking=no root@${HOST} "qm importdisk $VMID ${UPLOAD_DIR}/${SECONDARY_DISKS[$i]}.img ${SECONDARY_DATASTORES[$i]}"
    ssh -o StrictHostKeyChecking=no root@${HOST} "qm rescan --vmid $VMID"
    ssh -o StrictHostKeyChecking=no root@${HOST} "qm set $VMID --virtio${x} ${SECONDARY_DATASTORES[$i]}:vm-${VMID}-disk-${x},discard=on"
    ((x++))
done