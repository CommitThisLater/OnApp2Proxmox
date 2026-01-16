#!/bin/bash
#
# OnApp to Proxmox migration script
#
# This script migrates a VM from OnApp to Proxmox, handling disk exports, network configuration, and VM creation.
#
# Usage:
#  ./migrate -i <vm_id>
#
# Options:
#   -i, --onapp-vmid <id>                  OnApp Virtual Machine identifier (required).
#   -r                                     The VM being migrated is a Virtual Router.
#   --host <hostIP>                        Specify a specific Proxmox host (e.g., 192.168.1.100).
#   -b, --best-host                        Select the best Proxmox host based on available memory, defaults to true if no host is specified.
#   -n, --vmname <name>                    Choose a different name for the VM in Proxmox (lowercase letters, numbers, hyphens).
#   -o, --os <linux|windows|other|auto>    Operating system type of the VM (required), defaults to auto-detection.
#   --boot                                 Start the VM in Proxmox after migration (optional).
#   --nosuspend                            Do not suspend the source VM in OnApp after migration (optional).
#   --nicid <nic_id>                       Specify a specific PCI NIC ID to migrate (optional, used to prevent issues with Windows interface detection).
# Reference documentation:
#
# OnApp API docs, https://www.virtuozzo.com/onapp-cloud-docs/7.0/api-guide
# Proxmox - qm, https://pve.proxmox.com/pve-docs/chapter-qm.html
# Proxmox - pvesh, https://pve.proxmox.com/pve-docs/chapter-pvesh.html
#
# Run this script from any OnApp Hypervisor or ideally the OnApp Backup Server.
# Make sure the server where this script is run has SSH key access to the Proxmox hosts listed in $hosts below.
# Drop the script into /usr/local/bin/migrate, chmod +x /usr/local/bin/migrate
# Example usage: migrate -i qkhdnvszackhck
# You will find the OnApp VM ID (qkhdnvszackhck) in the URL of the Virtual Machine.
#
# In most cases Linux VMs will migrate with no further actions required.
# For Windows VMs, you may need to uninstall the OnApp Guest Tools and install the Proxmox Guest Tools.
# In most cases, Windows VMs will also require the network interface to be reconfigured inside the OS.
#
# This script is designed for OnApp Integrated Storage, if you use a SAN or other storage backend,
# you may need to modify the disk export section accordingly, SAN uses LVM to manage disks.
#
###

if [ -z "$BASH_VERSION" ]; then
  if command -v bash >/dev/null 2>&1; then
    exec bash "$0" "$@"
  else
    echo "This script requires Bash."
    exit 1
  fi
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  usage
fi

set -e

export LIBGUESTFS_BACKEND=direct

lockFile="/var/run/o2p.lock"
if ! mkdir "$lockFile" 2>/dev/null; then
  echo "Script is already running ($lockFile exists)"
  exit 1
fi

########################################################################
################## Configurations for your environment #################
########################################################################
#
#OnApp API credentials
username="email@example.com"
apiKey="1fe72b1ht5slbda8d28bab0c82f9edfh7ue832b3"
apiUrl="http://10.0.2.1/"
#
# A list of all proxmox hosts in the cluster (SSH key must be added)
# This is an array, eg. hosts=("237.84.2.178" "38.0.101.76")
# Hosts in this list will be checked for available memory.
hosts=("192.168.20.2" "192.168.20.3" "192.168.20.4")
#
# The directory at the destination to store disk images
# Make sure this directory exists and has ample space
uploadDir="/migration"
#
# The local directory to store disk images
# Make sure this directory exists and has ample space
localDir="/storage"
#
# The SSH user to use for Proxmox
sshUser="root"
#
# The datastore to use for the primary disk
# This is the name of the Proxmox storage
primaryDatastore="ceph"
#
# The datastore to use for secondary disks
# This is the name of the Proxmox storage
# If you have multiple secondary disks, they will all be placed here
secondaryDatastoreDefault="ceph"
#
########################################################################
############# End of configurations for your environment ###############
########################################################################

cd "$localDir"

disksOnline=false
disksCopied=false
# Cleanup function / trap exit
cleanup() {

  if [[ "$setHelp" == true ]]; then
    rmdir "$lockFile" 2>/dev/null || true
    exit 0
  fi

  notify "Cleaning up resources... (DO NOT INTERRUPT!)"
  rmdir "$lockFile" 2>/dev/null || true

  if [[ -f "$fwFile" ]]; then
    rm -f "$fwFile"
  fi

  # Remove local disk images
  if [[ -f "${primaryDisk}.img" ]]; then
    rm -f "${primaryDisk}.img"
  fi

  if [[ -v secondaryDisks && ${#secondaryDisks[@]} -gt 0 ]]; then
    for i in "${!secondaryDisks[@]}"; do
      if [[ -f "${secondaryDisks[$i]}.img" ]]; then
        rm -f "${secondaryDisks[$i]}.img"
      fi
    done
  fi

  # Remove remote disk images from Proxmox host
  if [[ "$disksCopied" == true ]]; then
    if [[ -n "$host" ]]; then
      ssh -o StrictHostKeyChecking=no ${sshUser}@${host} "rm -f ${uploadDir}/${primaryDisk}.img" || true

      if [[ -v secondaryDisks && ${#secondaryDisks[@]} -gt 0 ]]; then
        for i in "${!secondaryDisks[@]}"; do
          ssh -o StrictHostKeyChecking=no ${sshUser}@${host} "rm -f ${uploadDir}/${secondaryDisks[$i]}.img" || true
        done
      fi
    fi
  fi

  # Bring OnApp disks offline if still online
  if [[ "$disksOnline" == true ]]; then
    onappstore offline uuid="${primaryDisk}"

    if [[ -v secondaryDisks && ${#secondaryDisks[@]} -gt 0 ]]; then
      for i in "${!secondaryDisks[@]}"; do
        onappstore offline uuid="${secondaryDisks[$i]}"
      done
    fi
  fi
}
trap cleanup EXIT SIGINT SIGTERM

notify() {
  purple='\033[0;35m'
  red='\033[0;31m'
  green='\033[0;32m'
  reset='\033[0m'

  case "$1" in
    -e)
      shift
      echo -e "${red}$1${reset}"
      ;;
    -g)
      shift
      echo -e "${green}$1${reset}"
      ;;
    *)
      echo -e "${purple}$1${reset}"
      ;;
  esac
}

get_vm_field() {
  local json="$1"
  local field="$2"
  if [[ "$onappMachineType" == "virtual_routers" ]]; then
    echo "$json" | jq -r ".virtual_router.$field // empty"
  else
    echo "$json" | jq -r ".virtual_machine.$field // empty"
  fi
}

usage() {
  echo "Usage: $0 [OPTIONS]"
  echo
  echo "This script migrates a VM from OnApp to Proxmox, handling disk exports, network configuration, and VM creation."
  echo
  echo "Options:"
  echo "  -i, --onapp-vmid <id>                  OnApp Virtual Machine identifier (required)."
  echo "  -r                                     The VM being migrated is a Virtual Router."
  echo "  --host <hostIP>                        Specify a specific Proxmox host (e.g., 192.168.1.100)."
  echo "  -b, --best-host                        Select the best Proxmox host based on available memory, defaults to true if no host is specified."
  echo "  -n, --vmname <name>                    Choose a different name for the VM in Proxmox (lowercase letters, numbers, hyphens)."
  echo "  -o, --os <linux|windows|other|auto>    Operating system type of the VM (required), defaults to auto-detection."
  echo "  --boot                                 Start the VM in Proxmox after migration (optional)."
  echo "  --nosuspend                            Do not suspend the source VM in OnApp after migration (optional)."
  echo
  echo " Example:"
  echo "  $0 -i abcdefghijklmn"
  echo "  $0 -i abcdefghijklmn --boot"
  echo
  exit 1
}

host=""
bestHost=false
vmName=""
osType=""
errorMsg=""
onappMachineType="virtual_machines"
setHelp=false
suspendSourceVM=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --onapp-vmid|-i)
      onappVmid=$2
      if ! [[ "$onappVmid" =~ ^[a-z0-9]{14}$ ]]; then
        errorMsg+="Error: onappVmid must be 14 lowercase letters (a–z) or numbers (0–9).\n"
      fi
      shift 2
      ;;
    --host)
      host=$2
      if ! [[ "$host" =~ ^(([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]] \
         && ! [[ "$host" =~ ^[a-fA-F0-9:]+$ ]]; then
        errorMsg+="Error: host must be a valid IPv4 or IPv6 address.\n"
      fi
      shift 2
      ;;
    --best-host|-b)
      bestHost=true
      shift 1
      ;;
    --vmname|-n)
      vmName=$2
      shift 2
      ;;
    --os|-o)
      osType=$(echo "$2" | tr '[:upper:]' '[:lower:]')
      if [[ "$osType" != "linux" && "$osType" != "windows" && "$osType" != "other" && "$osType" != "auto" ]]; then
        errorMsg+="Error: Invalid OS type. Allowed values are linux, windows, other, or auto.\n"
      fi
      shift 2
      ;;
    --boot)
      startVM=true
      shift 1
      ;;
    --nosuspend)
      suspendSourceVM=false
      shift 1
      ;;
    --debug)
      debugMode=true
      notify "Debug mode enabled."
      shift 1
      ;;
    -r)
      notify "The VM has been flagged as a Virtual Router (-r)"
      onappMachineType="virtual_routers"
      shift 1
      ;;
    -h|--help)
      setHelp=true
      usage
      ;;
    *)
      errorMsg+="Error: Unknown option '$1'.\n"
      shift 1
      ;;
  esac
done

# Auto detect OS type if not specified
if [[ -z "$osType" ]]; then
  osType="auto"
  notify "OS type not specified, defaulting to auto-detection."
fi

# Validate host/best-host logic
if [[ -n "$host" && "$bestHost" == true ]]; then
  notify -e "Error: You cannot specify both --host and --best-host."
  usage
elif [[ -z "$host" && "$bestHost" == false ]]; then
  notify "No host specified, automatically selecting the best host based on available memory."
  bestHost=true
fi

if [[ -z "$onappVmid" ]]; then
  errorMsg+="Error: --onapp-vmid is required.\n"
fi

# Show all collected errors
if [[ -n "$errorMsg" ]]; then
  notify -e "$errorMsg"
  usage
fi

# Check API access
notify "Checking API access with OnApp..."
httpCode=$(curl -s -o /dev/null -w "%{http_code}" -u "$username:$apiKey" "$apiUrl/settings/license.json")

if [[ "$httpCode" != "200" ]]; then
  notify -e "Error: Failed to authenticate with OnApp API (HTTP $httpCode)."
  exit 1
else
  notify "API credentials are valid."
fi

notify -g "Migration script started at: $(date)"
startTime=$(date +%s)

# Check if the VM exists in OnApp
notify "Checking if VM with ID $onappVmid exists in OnApp..."
response=$(curl -s -u "$username:$apiKey" "$apiUrl/${onappMachineType}/$onappVmid.json")

vm_id=$(get_vm_field "$response" "id")

if [[ -z "$vm_id" || "$vm_id" == "null" ]]; then
  notify -e "Error: ${onappMachineType%?} with ID $onappVmid does not exist in OnApp or invalid response."
  exit 1
fi

sshExec() {
  ssh -o StrictHostKeyChecking=no ${sshUser}@"$1" "$2"
}

getBestHost() {
  local bestHost=""
  local maxFreeMem=0

  for ip in "${hosts[@]}"; do
    nodeName=$(sshExec "$ip" "hostname")
    nodeJson=$(sshExec "$ip" "pvesh get /nodes/$nodeName/status --output-format json" 2>/dev/null)

    if [[ -z "$nodeJson" ]]; then
      continue
    fi

    freeMem=$(echo "$nodeJson" | jq -r '.memory.total - .memory.used')

    if (( freeMem > maxFreeMem )); then
      maxFreeMem=$freeMem
      bestHost=$ip
    fi
  done

  echo "$bestHost"
}

# Check if the host is specified or if we need to find the best host
if [[ "$osType" == "auto" ]]; then
  notify "Auto-detecting OS type for VM ID: $onappVmid"
  osType=$(get_vm_field "$response" "operating_system")

  osType=$(echo "$osType" | tr '[:upper:]' '[:lower:]')
  if [[ "$osType" == "freebsd" ]]; then
    osType="other"
  fi

  if [[ -z "$osType" ]]; then
    notify -e "Error: Unable to auto-detect OS type."
    exit 1
  fi

  if [[ "$osType" != "linux" && "$osType" != "windows" ]]; then
    osType="other"
  fi
  notify "Detected OS type as: $osType"
fi

if [[ "$bestHost" == true ]]; then
  host=$(getBestHost)

  if [[ -n "$host" ]]; then
    notify "Selected best Proxmox host based on available memory: $host"
  else
    notify -e "Error: No suitable Proxmox host found."
    exit 1
  fi
fi

# Use the OnApp VM label as the VM name if no name is specified
if [[ -z "$vmName" ]]; then
  notify "A VM name was not specified, using the OnApp VM label."
  onappLabel=$(get_vm_field "$response" "label")

  vmName=$(echo "$onappLabel" \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/[^a-z0-9]/-/g' \
  | sed 's/-\+/-/g' \
  | sed 's/^-//' \
  | sed 's/-$//')

  notify "Using VM name: $vmName"
fi

# Check the VM status in OnApp before proceeding
notify "Checking VM status for VM ID: $onappVmid"
statusJson=$(curl -s -u "$username:$apiKey" "$apiUrl/${onappMachineType}/$onappVmid/status.json")

isBuilt=$(get_vm_field "$statusJson" "built")
isLocked=$(get_vm_field "$statusJson" "locked")
isBooted=$(get_vm_field "$statusJson" "booted")

if [[ "$isBuilt" != "true" ]]; then
  notify -e "Error: VM is not built yet."
  exit 1
fi

if [[ "$isLocked" == "true" ]]; then
  notify -e "Error: VM is currently locked."
  exit 1
fi

if [[ "$isBooted" == "true" ]]; then
  notify -e "Error: VM is currently running. Please shut it down before migration."
  exit 1
fi

notify "VM status looks okay, proceeding with migration."

checkSshAccess() {
  local user="$1"
  local ip="$2"

  notify "Checking SSH access for ${user}@${ip}..."

  if ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no "${user}@${ip}" exit 2>/dev/null; then
    notify "SSH access is available without a password for ${user}@${ip}"
    return 0
  else
    notify -e "SSH access failed for ${user}@${ip} - Make sure SSH is available with RSA key authentication."
    exit 1
  fi
}

checkDatastore() {
  local datastore="$1"
  local pveOutput=$(ssh -o StrictHostKeyChecking=no "${sshUser}@${host}" "pvesm status")

  if echo "$pveOutput" | awk '{print $1}' | grep -Fxq "$datastore"; then
    status=$(echo "$pveOutput" | awk -v ds="$datastore" '$1 == ds {print $3}')
    if [[ "$status" == "active" ]]; then
      notify "Datastore '$datastore' exists and is active."
    else
      notify -e "Error: Datastore '$datastore' exists but is NOT active."
      exit 1
    fi
  else
    notify -e "Error: Datastore '$datastore' does not exist."
    exit 1
  fi
}

# CPU Core & Memory
notify "Fetching CPU and Memory configuration from OnApp for VM ID: $onappVmid"
read -r memory cores < <(
  echo "$(get_vm_field "$response" "memory") $(get_vm_field "$response" "cpus")"
)

if [[ -z "$memory" || -z "$cores" ]]; then
  notify -e "Error: Failed to fetch memory or CPU values from OnApp API."
  exit 1
fi

notify "Source VM has $memory MB RAM and $cores CPU cores"

### Disks
declare -A diskMap

notify "Fetching disk information for VM ID: $onappVmid"

swapSize=""
while read -r identifier size primary isSwap; do
  diskMap["$identifier"]="$size|$primary|$isSwap"
  if [[ "$isSwap" == "true" || "$isSwap" == "1" ]]; then
    swapSize=$((size * 1024))
  else
    noSwapSet=true
  fi
done < <(
  curl -s -u "$username:$apiKey" "$apiUrl/${onappMachineType}/$onappVmid/disks.json" |
    jq -r '.[].disk | "\(.identifier) \(.disk_size) \(.primary) \(.is_swap)"'
)
if [[ "$noSwapSet" == true ]]; then
  notify "This VM does not have a swap disk"
else
  notify "Detected swap size: ${swapSize} MB"
fi

# Separate primary and secondary disks
primaryDisk=""
secondaryDisks=()
for id in "${!diskMap[@]}"; do
  IFS='|' read -r size primary isSwap <<< "${diskMap[$id]}"
  if [[ "$primary" == "true" ]]; then
    primaryDisk="$id"
  elif [[ "$isSwap" == "false" ]]; then
    secondaryDisks+=("$id")
  else
    notify "Skipping swap disk: $id"
  fi
done

if [[ -z "$primaryDisk" ]]; then
  notify -e "Error: No primary disk found in OnApp API response."
  exit 1
fi

notify "Primary disk: $primaryDisk"
if [[ ${#secondaryDisks[@]} -gt 0 ]]; then
  notify "Secondary disks: ${secondaryDisks[*]}"
else
  notify "No secondary disks detected."
fi

### NICs
declare -A nicMap

# Get NICs from OnApp API
notify "Fetching network interfaces for VM ID: $onappVmid"
while read -r identifier mac mtu primary; do
  nicMap["$identifier"]="$mac|${mtu:-1500}|$primary|nic"
done < <(
  curl -s -u "$username:$apiKey" "$apiUrl/${onappMachineType}/$onappVmid/network_interfaces.json" |
    jq -r '.[].network_interface | "\(.identifier) \(.mac_address) \(.rate_limit) \(.primary)"'
)

# Get SDN interfaces from OnApp API
notify "Fetching SDN interfaces for VM ID: $onappVmid"
sdnCount=0
while read -r identifier mac label network_id primary; do
  if [[ -n "$identifier" && "$identifier" != "null" ]]; then
    nicMap["$identifier"]="$mac|1500|${primary:-false}|sdn|$label|$network_id"
    ((sdnCount++))
  fi
done < <(
  curl -s -u "$username:$apiKey" "$apiUrl/${onappMachineType}/$onappVmid/network_joins.json" |
    jq -r '.[].network_join | "\(.identifier) \(.mac_address) \(.label // "SDN") \(.network_id) \(.primary)"' 2>/dev/null || echo ""
)

if [[ $sdnCount -gt 0 ]]; then
  notify "Found $sdnCount SDN interface(s)"
fi

# Normalize NIC data (MTU is not in OnApp, so we set a default value of 1500)
for key in "${!nicMap[@]}"; do
  IFS='|' read -r mac mtu primary type label network_id <<< "${nicMap[$key]}"
  if [[ "$type" == "sdn" ]]; then
    nicMap["$key"]="$mac|1500|$primary|sdn|$label|$network_id"
  else
    nicMap["$key"]="$mac|1500|$primary|nic"
  fi
done

# Get bridges from Proxmox
notify "Fetching available Proxmox bridges from $host"
remoteNodeName=$(sshExec "$host" "hostname")
bridgeListJson=$(sshExec "$host" "pvesh get /nodes/$remoteNodeName/network --output-format=json")

# Extract bridge interface and comments
bridgeList=$(printf '%s' "$bridgeListJson" \
  | jq -r '.[] | select(.type == "bridge") | "\(.iface)|bridge|\((.comments // "(no comment)") | gsub("\n"; ""))"')

if [[ -z "$bridgeList" ]]; then
  notify -e "Error: No bridge interfaces found on Proxmox host."
  exit 1
fi

# Get SDN vnets from Proxmox
notify "Fetching available Proxmox SDN vnets from $host"
sdnVnetList=$(sshExec "$host" "pvesh get /cluster/sdn/vnets --output-format=json" 2>/dev/null || echo "[]")

# Extract vnet names and zones
sdnVnetListFormatted=$(printf '%s' "$sdnVnetList" \
  | jq -r '.[] | "\(.vnet)|sdn|SDN VNet in zone: \(.zone // "unknown")"' 2>/dev/null || echo "")

# Combine bridges and SDN vnets into a single list
if [[ -n "$sdnVnetListFormatted" ]]; then
  networkList=$(printf "%s\n%s" "$bridgeList" "$sdnVnetListFormatted")
  notify "Found SDN vnets on Proxmox host"
else
  networkList="$bridgeList"
  notify "No SDN vnets found on Proxmox host"
fi

# Prepare network array (bridges + SDN vnets)
mapfile -t networkArray < <(awk -F'|' '{print $1}' <<< "$networkList")
mapfile -t networkTypeArray < <(awk -F'|' '{print $2}' <<< "$networkList")
mapfile -t networkCommentArray < <(awk -F'|' '{print $3}' <<< "$networkList")

# Get user input for NICs
nics=()
for id in "${!nicMap[@]}"; do
  IFS='|' read -r mac mtu primary type label network_id <<< "${nicMap[$id]}"

  echo
  if [[ "$type" == "sdn" ]]; then
    echo "SDN Interface: $id (MAC: $mac | MTU: ${mtu:-1500} | Primary: $primary | Label: ${label:-N/A} | Network ID: ${network_id:-N/A})"
  else
    echo "NIC: $id (MAC: $mac | MTU: ${mtu:-1500} | Primary: $primary)"
  fi

  if [[ ${#networkArray[@]} -eq 1 ]]; then
    selectedNetwork="${networkArray[0]}"
    notify "Only one network (${selectedNetwork}) available. Selecting it automatically."
  else
    echo "Select the network to use for this interface:"
    for i in "${!networkArray[@]}"; do
      networkType="${networkTypeArray[$i]}"
      networkComment="${networkCommentArray[$i]}"
      if [[ "$networkType" == "sdn" ]]; then
        printf "  [%d] %s (SDN) - %s\n" "$i" "${networkArray[$i]}" "$networkComment"
      else
        printf "  [%d] %s (Bridge) - %s\n" "$i" "${networkArray[$i]}" "$networkComment"
      fi
    done

    while true; do
      read -p "Enter number (0-$(( ${#networkArray[@]} - 1 ))): " selectedIndex
      if [[ "$selectedIndex" =~ ^[0-9]+$ ]] && (( selectedIndex >= 0 && selectedIndex < ${#networkArray[@]} )); then
        selectedNetwork="${networkArray[$selectedIndex]}"
        break
      else
        echo "Invalid selection. Please enter a number between 0 and $(( ${#networkArray[@]} - 1 ))."
      fi
    done
  fi

  nicString="${selectedNetwork},${mac},${mtu:-1500}"
  if [[ "$primary" == "true" ]]; then
    nics=("$nicString" "${nics[@]}")
  else
    nics+=("$nicString")
  fi
done

### IP Addresses
ipAddresses=()

notify "Fetching IP addresses for VM ID: $onappVmid"
ipJson=$(curl -s -u "$username:$apiKey" "$apiUrl/${onappMachineType}/$onappVmid/ip_addresses.json")

# Extract just the IP addresses
readarray -t ipAddresses < <(
  echo "$ipJson" | jq -r '.[] | .ip_address_join.ip_address.address'
)

notify "IP addresses detected:"
printf '  %s\n' "${ipAddresses[@]}"

if [[ "$debugMode" == true ]]; then
  echo "DEBUG: Swap Size: $swapSize"
  echo "DEBUG: Host: $host"
  echo "DEBUG: VM Name: $vmName"
  echo "DEBUG: Cores: ${cores:-4}"
  echo "DEBUG: Memory: ${memory:-4096}"
  echo "DEBUG: primaryDisk: $primaryDisk"
  echo "DEBUG: primaryDatastore: $primaryDatastore"
  echo "DEBUG: nics: ${nics[*]}"
  echo "DEBUG: secondaryDisks: ${secondaryDisks[*]}"
  echo "DEBUG: secondaryDatastores: $secondaryDatastoreDefault"
fi

checkNetwork() {
  local network="$1"

  # Check if it's a bridge
  local bridgeCheck=$(ssh -o StrictHostKeyChecking=no "${sshUser}@${host}" "brctl show $network 2>/dev/null")
  if [[ $? -eq 0 && -n "$bridgeCheck" ]]; then
    notify "Network bridge '$network' exists on $host."
    return 0
  fi

  # Check if it's an SDN vnet
  local sdnCheck=$(ssh -o StrictHostKeyChecking=no "${sshUser}@${host}" "pvesh get /cluster/sdn/vnets/$network --output-format=json 2>/dev/null")
  if [[ $? -eq 0 && -n "$sdnCheck" ]]; then
    notify "SDN vnet '$network' exists on $host."
    return 0
  fi

  notify -e "Error: Network '$network' does not exist on $host (not a bridge or SDN vnet)."
  exit 1
}

createDiskImage() {
  local disk="$1"
  notify "Exporting the OnApp disk image to file for $disk - some of these steps may take a while..."

  notify " - Getting the frontend uuid for the host"
  frontend=$(onappstore getid | grep -o 'uuid=[^ ]*' | cut -d= -f2)
  if [ $? -ne 0 ]; then
    notify -e "Error: Failed to get frontend ID."
    return 1
  fi

  notify " - Bringing the disk online"
  onappstore online uuid="${disk}" frontend_uuid="${frontend}"
  if [ $? -ne 0 ]; then
    notify -e "Error: Failed to bring the frontend online, check the disk health in OnApp"
    return 1
  fi
  disksOnline=true

  notify " - Creating disk image for $disk"
  dd if="/dev/mapper/${disk}" of="${disk}.img" bs=1M
  if [ $? -ne 0 ]; then
    notify -e "Error: Disk image creation failed."
    return 1
  fi

  notify " - Bringing the disk offline"
  onappstore offline uuid="${disk}"
  disksOnline=false

  notify "Disk image creation for $disk successful."
  return 0
}

checkSshAccess "${sshUser}" "$host"
checkDatastore "$primaryDatastore"

if [[ "$secondaryDatastoreDefault" != "$primaryDatastore" ]]; then
    checkDatastore "$secondaryDatastoreDefault"
fi

# Standard way to get the next VM ID in Proxmox
# vmid=$(ssh ${sshUser}@${host} "pvesh get /cluster/nextid")

# We want migrated VMs to start at 200
vmid=$(ssh "${sshUser}@${host}" \
  "pvesh get /cluster/resources --type vm --output-format json | jq -r '.[].vmid' | sort -n" \
  | awk 'BEGIN {min=200}
         {used[$1]=1}
         END {for (i=min; ; i++) if (!(i in used)) {print i; exit}}')

if [[ -z "$vmid" ]]; then
  notify -e "Error: Unable to get a valid vmid from Proxmox."
  exit 1
else
  notify "Using next available VM ID: $vmid"
fi

if [[ -e "${primaryDisk}.img" ]]; then
  rm "${primaryDisk}.img"
fi
createDiskImage "$primaryDisk"

if [[ -v secondaryDisks && ${#secondaryDisks[@]} -gt 0 ]]; then
  for i in "${!secondaryDisks[@]}"; do
    if [[ -e "${secondaryDisks[$i]}.img" ]]; then
      rm "${secondaryDisks[$i]}.img"
    fi
    createDiskImage "${secondaryDisks[$i]}"
  done
fi

notify "Running virt-customize to prepare the disk image for Proxmox..."

# Linux specific customisations
if [[ "$osType" == "linux" ]]; then

  if [[ -n "$swapSize" ]]; then
    notify "A swap size was provided, creating swap on the primary disk..."

    qemu-img resize -f raw "${primaryDisk}.img" +"${swapSize}M"

    virt-customize -a "${primaryDisk}.img" \
      --run-command '
        . /etc/os-release
        case "$ID" in
          debian|ubuntu)
            apt-get update && apt-get install -y cloud-guest-utils
            ;;
          rhel|centos|rocky|almalinux|fedora)
            yum install -y cloud-utils-growpart || dnf install -y cloud-utils-growpart
            ;;
        esac
      ' \
      --run-command 'growpart /dev/sda 1 && resize2fs /dev/sda1'


    virt-customize -a "${primaryDisk}.img" \
      --run-command "dd if=/dev/zero of=/swapfile bs=1M count=$swapSize" \
      --run-command "chmod 600 /swapfile" \
      --run-command "mkswap /swapfile"

    virt-cat --format=raw -a "${primaryDisk}.img" /etc/fstab

    virt-customize -a "${primaryDisk}.img" \
      --run-command "sed -i '/swap/d' /etc/fstab" \
      --run-command "echo '/swapfile none swap sw 0 0' >> /etc/fstab"

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

  virt-customize -a "${primaryDisk}.img" \
    --run-command 'mkdir -p /boot/grub /boot/grub2' \
    --run-command 'echo "(hd0) /dev/sda" > /boot/grub/device.map 2>/dev/null || true' \
    --run-command 'echo "(hd0) /dev/sda" > /boot/grub2/device.map 2>/dev/null || true' \
    --run-command 'if command -v grub-install >/dev/null; then grub-install /dev/sda; fi' \
    --run-command 'if command -v grub2-install >/dev/null; then grub2-install /dev/sda; fi' \
    --run-command 'if command -v update-grub >/dev/null; then update-grub; fi' \
    --run-command 'if command -v grub2-mkconfig >/dev/null; then grub2-mkconfig -o /boot/grub2/grub.cfg; fi' \
    --run-command 'find /boot -type f -exec sed -i "s|/dev/sda|/dev/vda|g" {} +'

  # Install qemu-guest-agent
  virt-customize -a "${primaryDisk}.img" \
    --run-command '
      . /etc/os-release
      case "$ID" in
        debian|ubuntu)
          apt-get update && apt-get install -y qemu-guest-agent
          ;;
        rhel|centos|rocky|almalinux|fedora)
          yum install -y qemu-guest-agent || dnf install -y qemu-guest-agent
          ;;
      esac
    ' \
  --firstboot-command "systemctl enable --now qemu-guest-agent"

  # Show the modified /etc/fstab
  virt-cat --format=raw -a "${primaryDisk}.img" /etc/fstab
fi

if [[ "$osType" == "windows" ]]; then
  # Limited libguestfs support for Windows, shouldn't be necessary anyway.
  # Possible actions: virt-cp, virt-cat, firstboot?
  :
fi

if [[ "$osType" == "other" ]]; then
  # This hasn't been tested yet
  :
fi

# Prepare network args for Proxmox
netArgs=()
for nic in "${nics[@]}"; do
  bridge=$(echo "$nic" | cut -d',' -f1)
  macaddr=$(echo "$nic" | cut -d',' -f2)
  mtu=$(echo "$nic" | cut -d',' -f3)
  checkNetwork "$bridge"

  if [[ -z "$mtu" || "$mtu" -lt 576 ]]; then
    mtu=1500
  fi

  netArgs+=("--net${#netArgs[@]} virtio,bridge=${bridge},macaddr=${macaddr^^},mtu=${mtu},firewall=1")
done
netArgsStr="${netArgs[@]}"

# These can be modified based on specific requirements
case "$osType" in
  linux)   pmosType="l26" ;;
  windows) pmosType="win11" ;;
  *)       pmosType="other" ;;
esac

# Set the machine type for Proxmox
machineType="q35"

# Check resources on the selected Proxmox host
notify "Checking available resources on Proxmox host: $host"
nodeName=$(sshExec "$host" "hostname")
resources=$(sshExec "$host" "pvesh get /nodes/$nodeName/status --output-format json")

if [[ -z "$resources" ]]; then
  notify -e "Error: Unable to fetch resources from Proxmox host $host."
  exit 1
fi

availableMemory=$(echo "$resources" | jq -r '.memory.total - .memory.used')
availableCores=$(echo "$resources" | jq -r '.cpuinfo.cores')

if [[ -z "$availableMemory" || -z "$availableCores" ]]; then
  notify -e "Error: Unable to determine available resources on Proxmox host $host."
  exit 1
fi

notify "Available memory: $((availableMemory / 1024 / 1024)) MB"
notify "Available CPU cores: $availableCores"

# 8GB for KVM overhead
if (( memory > (availableMemory / 1024 / 1024) - 8192 )); then
  notify -e "Error: Requested memory ($memory MB) exceeds available memory on Proxmox host ($((availableMemory / 1024 / 1024)) MB)."
  exit 1
fi

if (( cores > availableCores )); then
  notify -e "Error: Requested CPU cores ($cores) exceed available cores on Proxmox host ($availableCores)."
  exit 1
fi

# Suspend the source VM
if [[ "$suspendSourceVM" == true ]]; then
  notify "Suspending the source VM on OnApp..."
  curl -s -X POST -u "$username:$apiKey" "$apiUrl/${onappMachineType}/$onappVmid/suspend.json" &> /dev/null
  if [[ $? -ne 0 ]]; then
    notify -e "Error: Failed to suspend the source VM in OnApp."
    exit 1
  fi
else
  notify "The source VM will not be suspended, please do it manually."
fi

# Transfer and build the VM on Proxmox
notify "Transferring primary disk image to Proxmox host: $host - this may take a while..."
disksCopied=true
scp "${primaryDisk}.img" "${sshUser}@${host}:${uploadDir}/${primaryDisk}.img"
notify "Primary disk image transferred successfully."
notify "Creating VM on Proxmox host: $host and importing the disk image..."
sshExec "$host" "qm create $vmid \
  --name $vmName \
  --machine $machineType \
  --virtio0 ${primaryDatastore}:0,discard=on,import-from=${uploadDir}/${primaryDisk}.img \
  --agent enabled=1,type=virtio,freeze-fs-on-backup=1 \
  --ostype $pmosType \
  --cpu cputype=host \
  --cores ${cores:-4} \
  --memory ${memory:-4096} \
  $netArgsStr \
  $cloudInitArgsStr \
  --onboot 1 \
  --scsihw virtio-scsi-pci"

# Transfer and build the secondary disks (if any)
if [[ -v secondaryDisks && ${#secondaryDisks[@]} -gt 0 ]]; then
  notify "Transferring and importing secondary disks into Proxmox host: $host - this may take a while..."
  diskId=1
  for disk in "${secondaryDisks[@]}"; do
    scp "${disk}.img" "${sshUser}@${host}:${uploadDir}/${disk}.img"
    sshExec "$host" "qm importdisk $vmid ${uploadDir}/${disk}.img ${secondaryDatastoreDefault}"
    sshExec "$host" "qm rescan --vmid $vmid"
    sshExec "$host" "qm set $vmid --virtio${diskId} ${secondaryDatastoreDefault}:vm-${vmid}-disk-${diskId},discard=on"
    diskId=$((diskId + 1))
  done
fi

# Build Proxmox firewall config for VM
fwFile="/tmp/${vmid}.fw"
notify "Building firewall file: $fwFile"

{
  # Static [OPTIONS] lines
  echo "[OPTIONS]"
  echo
  options=(
    "policy_in: DROP"
    "log_level_out: nolog"
    "log_level_in: nolog"
    "radv: 0"
    "policy_out: DROP"
    "ipfilter: 1"
    "dhcp: 0"
    "ndp: 0"
    "macfilter: 1"
    "enable: 1"
  )

  for line in "${options[@]}"; do
    echo "$line"
  done

  echo
  echo "[IPSET ipfilter-net0] # ipfilter-net0"

  # Dynamic IPs
  for ip in "${ipAddresses[@]}"; do
    echo "$ip # net0"
  done

  echo
  echo "[RULES]"
  echo
  rules=(
    "IN ACCEPT -dest +guest/ipfilter-net0 -log nolog"
    "OUT ACCEPT -source +guest/ipfilter-net0 -log nolog"
    "OUT DROP -log nolog # Block everything else"
  )

  for line in "${rules[@]}"; do
    echo "$line"
  done
} > "$fwFile"

notify "Firewall file $fwFile created with the following IPs:"
printf '  %s\n' "${ipAddresses[@]}"

# Copy the file to Proxmox
scp "$fwFile" "${sshUser}@${host}:/etc/pve/firewall/${vmid}.fw"

if [[ $? -eq 0 ]]; then
  notify "Firewall file ${fwFile} successfully copied to /etc/pve/firewall/${vmid}.fw on $host"
else
  notify -e "Error: Failed to copy firewall file to Proxmox."
  exit 1
fi

if [[ "$startVM" == true ]]; then
  notify "The boot option was passed, the VM is being started."
  sshExec "$host" "qm start $vmid"
else
  notify "The VM will NOT be started after migration, start the VM manually."
fi

endTime=$(date +%s)
elapsedTime=$((endTime - startTime))
minutes=$((elapsedTime / 60))
seconds=$((elapsedTime % 60))

notify -g "Migration script ended at: $(date)"
notify -g "Total execution time: ${minutes} minutes and ${seconds} seconds"

