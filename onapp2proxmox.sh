#!/bin/bash
#
# OnApp to Proxmox migrations
#
# Example usage with two secondary disks, two NICs, and Linux OS:
# sh convert.sh --swap-size 1024 --host 192.168.117.213 --vmname vm-name --cores=8 --memory=8192 \
#  -p l7a3u8sngmrtc0:Ceph_Master -s 4u32reaicnk075:Ceph_Master -s fj8dndji9ed6g2:Ceph_Master \
#   --nics vmbr0,00:16:3e:25:dc:64,1500 vmbr1,00:16:3e:25:dc:65,9000 --os linux
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
    notify "Cleaning up resources... (DO NOT INTERRUPT!)"
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

notify() {
  purple='\033[0;35m'
  reset='\033[0m'
  echo -e "${purple}$1${reset}"
}

# Check running
if [[ -e ".lock" ]]; then
    notify "Script is already running (.lock exists)"
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
    echo "  --cores <numCores>                                                  Number of CPU cores (default: 4)"
    echo "  --memory <memoryMB>                                                 Amount of memory in MB (default: 4096)"
    echo "  --random-host                                                       Select a random Proxmox host from the predefined list"
    echo "  --vmname <vmName>                                                   Name of the VM (only lowercase letters, numbers, and '-' allowed)"
    echo "  --nics <bridge,macaddr,mtu> ...                                     Network interfaces for the VM (primary NIC is mandatory, for multiple NICs specify with --nics <bridge,macaddr,mtu> <bridge,macaddr,mtu> putting the primary first)"
    echo "  -p <primaryDisk>:<datastore>                                        Path to the primary disk and associated proxmox datastore"
    echo "  -s <secondaryDisk1>:<datastore> <secondaryDisk2>:<datastore> ...    Paths to secondary disks and associated datastores(optional)"
    echo "  --os <linux|windows|other>                                          Specify the OS type (mandatory)"
    echo
    echo "Example: $0 --swap-size 1024 --random-host --cores=8 --memory=8192 --vmname my-vm-01 --nics <vmbr0,00:1a:2b:3c:4d:5e,1500> -p pc2qwegju5f740:DataStoreSSD -s hk8udjdi85eg7n:DataStoreSSD k8jhd6wujkb79u:DataStoreHDD --nics vmbr0,00:16:3e:25:dc:64,1500 vmbr1,00:16:3e:25:dc:65,9000 --os linux"
    exit 1
}

# We need root
if [ "$(id -u)" -ne 0 ]; then
    notify "This script must be run as root or with sudo."
    usage
fi

# Validate inbound arguments
if [ $# -lt 7 ]; then
    notify "Error: At least 7 arguments are required."
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
            if [ -n "$swapSize" ]; then
                if ! [[ "$swapSize" =~ ^[0-9]+$ ]] || [ "$swapSize" -le 0 ]; then
                    notify "Error: Swap size must be a positive integer specified in MB."
                    usage
                fi
            fi
            shift 2
            ;;
        --cores)
            cores=$2
            shift 2
            ;;
        --memory)
            memory=$2
            shift 2
            ;;
        --host)
            host=$2
            if ! [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && ! [[ "$host" =~ ^[a-fA-F0-9:]+$ ]]; then
                notify "Error: host must be a valid IP address (IPv4 or IPv6)."
                usage
            fi
            shift 2
            ;;
        --random-host)
            randomHost=true
            shift 1
            ;;
        --vmname)
            vmName=$2
            if ! [[ "$vmName" =~ ^[a-z0-9-]+$ ]]; then
                notify "Error: vmName must only contain lowercase letters, numbers, and hyphens (-)."
                usage
            fi
            shift 2
            ;;
        -p) 
            if [[ "$2" =~ : ]]; then
                primaryDisk=$(echo $2 | cut -d':' -f1)
                primaryDatastore=$(echo $2 | cut -d':' -f2)
            else
                notify "Error: Primary disk and datastore must be in the format 'diskid:datastore'."
                usage
                exit 1
            fi

            # Validate both fields are populated
            if [[ -z "$primaryDisk" || -z "$primaryDatastore" ]]; then
                notify "Error: Both primaryDisk and primaryDatastore must be specified."
                usage
                exit 1
            fi

            # Validate primaryDisk format
            if [[ ! "$primaryDisk" =~ ^[a-zA-Z0-9]+$ ]]; then
                notify "Error: Invalid primaryDisk format: $primaryDisk. Must be alphanumeric."
                usage
                exit 1
            fi

            # Validate primaryDatastore format
            if [[ ! "$primaryDatastore" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                notify "Error: Invalid primaryDatastore format: $primaryDatastore. Must be alphanumeric, '_', or '-'."
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

            # Validate secondary disks and datastores
            if [[ ${#secondaryDisks[@]} -gt 0 && ${#secondaryDisks[@]} -ne ${#secondaryDatastores[@]} ]]; then 
                notify "Error: Number of secondary disks does not match number of secondary datastores." 
                usage
                exit 1
            fi
            shift 2
            ;;
        --nics)
            shift
            while [[ $# -gt 0 && "$1" =~ ^[a-zA-Z0-9_-]+,[0-9a-fA-F:]+,[0-9]+$ ]]; do
                # Validate each NIC format (bridge, macaddr, mtu)
                if [[ ! "$1" =~ ^[a-zA-Z0-9_-]+,[0-9a-fA-F:]+,[0-9]+$ ]]; then
                    notify "Error: Invalid NIC format. Use bridge,mac-address,mtu."
                    usage
                    exit 1
                fi
                nics+=("$1")
                shift
            done
            ;;
        --os)
            osType=$2
            if [[ "$osType" != "linux" && "$osType" != "windows" && "$osType" != "other" ]]; then
                notify "Error: Invalid OS type. Allowed values are linux, windows, or other."
                usage
            fi
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

# Ensure that only one of --host or --random-host is used
if [[ -n "$host" && "$randomHost" == true ]]; then
    notify "Error: You cannot specify both --host and --random-host."
    usage
elif [[ -z "$host" && "$randomHost" == false ]]; then
    notify "Error: You must specify either --host or --random-host."
    usage
fi

# Select a random host if --random-host is used
if [[ "$randomHost" == true ]]; then
    host=${hosts[$RANDOM % ${#hosts[@]}]}
    notify "Selected random Proxmox host: $host"
fi

# Validate required parameters
if [ -z "$host" ] || [ -z "$vmName" ] || [ -z "$osType" ]; then
    notify "Error: Missing required arguments."
    usage
fi

# Check inputs for testing
# notify "Params | --swap-size $swapSize --host $host --vmname $vmName"
# notify " -p ${primaryDisk}:${primaryDatastore}"
# notify " -s ${secondaryDisks[@]} ${secondaryDatastores[@]}"
# notify " --os $osType --nics ${nics[@]}" 
# notify " --cores ${cores:-4} --memory ${memory:-4096}"
# exit 0

check_ssh_access() {
    local user="$1"
    local ip="$2"

    notify "Checking SSH access for ${user}@${ip}..."

    if ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no "${user}@${ip}" exit 2>/dev/null; then
        notify "SSH access is available without a password for ${user}@${ip}"
        return 0
    else
        notify "SSH access failed for ${user}@${ip} - Make sure SSH is available with RSA key authentication."
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
            notify "Datastore '$datastore' exists and is active."
        else
            notify "Error: Datastore '$datastore' exists but is NOT active."
            exit 1
        fi
    else
        notify "Error: Datastore '$datastore' does not exist."
        exit 1
    fi
}

check_network() {
    local network=$1
    local pveOutput=$(ssh -o StrictHostKeyChecking=no ${sshUser}@${host} "brctl show $network")

    if [[ $? -eq 0 ]]; then
        notify "Network bridge '$network' exists on $host."
    else
        notify "Network bridge '$network' does not exist $host."
        exit 1
    fi
}

create_disk_image() {
    local disk=$1

    # Get frontend UUID
    frontend=$(onappstore getid | awk '{print $2}' | cut -d= -f2)
    if [ $? -ne 0 ]; then
        notify "Error: Failed to get frontend ID."
        return 1
    fi

    # Bring frontend online
    onappstore online uuid=$disk frontend_uuid=$frontend
    if [ $? -ne 0 ]; then
        notify "Error: Failed to bring the frontend online."
        return 1
    fi
    disksOnline=true

    # Create disk image
    dd if=/dev/mapper/$disk of=${disk}.img bs=1M
    if [ $? -ne 0 ]; then
        notify "Error: Disk image creation failed."
        return 1
    fi

    onappstore offline uuid=$disk
    disksOnline=false

    notify "Disk image creation for $disk successful."
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
    notify "Error: Unable to get a valid vmid from Proxmox."
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

    # If a swapsize was provided, create swap on the primary disk
    if [[ -n "$swapSize" ]]; then

        notify "A swap size was provided, creating swap on the primary disk..."

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
    fi

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
netArgs=()
for nic in "${nics[@]}"; do
    bridge=$(echo $nic | cut -d',' -f1)
    macaddr=$(echo $nic | cut -d',' -f2)
    mtu=$(echo $nic | cut -d',' -f3)
    check_network $bridge
    netArgs+=( "--net${#netArgs[@]} virtio,bridge=${bridge},macaddr=${macaddr^^},mtu=${mtu},firewall=1" )
done
netArgsStr="${netArgs[@]}"

# Set pmosType based on osType
if [[ "$osType" == "linux" ]]; then
    pmosType="l26"
elif [[ "$osType" == "windows" ]]; then
    pmosType="win2k8"
else
    pmosType="other"
fi

# Transfer and build the VM on Proxmox
scp ${primaryDisk}.img ${sshUser}@${host}:${uploadDir}/
ssh_exec "$host" "qm create $vmid \
  --name $vmName \
  --virtio0 ${primaryDatastore}:0,discard=on,import-from=${uploadDir}/${primaryDisk}.img \
  --agent enabled=1,type=virtio,freeze-fs-on-backup=1 \
  --ostype $pmosType \
  --cores ${cores:-4} \
  --memory ${memory:-4096} \
  $netArgsStr \
  --onboot 1 \
  --scsihw virtio-scsi-pci"

# Transfer and build the secondary disks (if any)
x=1
for i in "${!secondaryDisks[@]}"; do
    scp "${secondaryDisks[$i]}.img" ${sshUser}@${host}:${uploadDir}/
    ssh_exec "$host" "qm importdisk $vmid ${uploadDir}/${secondaryDisks[$i]}.img ${secondaryDatastores[$i]}"
    ssh_exec "$host" "qm rescan --vmid $vmid"
    ssh_exec "$host" "qm set $vmid --virtio${x} ${secondaryDatastores[$i]}:vm-${vmid}-disk-${x},discard=on"
    ((x++))
done
