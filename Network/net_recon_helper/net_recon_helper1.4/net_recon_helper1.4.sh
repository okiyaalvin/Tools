#!/bin/bash
# net_recon_helper1.4.sh
# OpenBash Pentesting Tools - Network Recon Helper
# Author: Your Pentest Team
# Disclaimer: For authorized security testing only.

LOG_DIR="logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/net_recon_$(date +%Y%m%d-%H%M%S).log"

######################
#   Helper Functions #
######################

pause(){
  read -n1 -rsp $'Press any key to continue...\n'
}

check_exit(){
  if [[ "$1" == "n" || "$1" == "N" ]]; then
    echo "[-] Authorization not complete. Exiting..."
    pause
    exit 1
  fi
}

sanitize_filename(){
  echo "$1" | tr '/:' '_'
}

log_command(){
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Target: $target | Tool: $1 | Command: $2 | Output: $3" | tee -a "$LOG_FILE"
}

ensure_tool(){
  local tool="$1"
  local install_cmd="$2"

  if ! command -v "$tool" &>/dev/null; then
    echo "[-] Tool '$tool' not found."
    read -p "Press Enter to install with default command [$install_cmd], or type custom command: " user_cmd
    if [[ -z "$user_cmd" ]]; then
      echo "[*] Installing with: $install_cmd"
      eval "$install_cmd"
    else
      echo "[*] Running custom install: $user_cmd"
      eval "$user_cmd"
    fi
  fi
}

######################
#      Disclaimer    #
######################

clear
echo "=============================================================="
echo "   OpenBash Pentesting Tools - Network Recon Helper v1.4"
echo "=============================================================="
echo
echo "[!] DISCLAIMER: Hacking or scanning without explicit written"
echo "    authorization from the system owner is illegal."
echo "    This tool is for authorized VAPT engagements ONLY."
echo
echo "=============================================================="
pause

######################
#   RoE & Checklist  #
######################

echo ">>> Step 1: Rules of Engagement & Checklist"
echo "Before continuing, confirm that the following documents are signed:"
echo "  1. Rules of Engagement (RoE)"
echo "  2. Signed Client Consent"
echo "  3. Scope of Work document"
echo "  4. Non-Disclosure Agreement (NDA)"
echo

read -p "Do you have a signed Rules of Engagement? (y/n): " roe
check_exit "$roe"

read -p "Do you have a signed Client Consent? (y/n): " consent
check_exit "$consent"

read -p "Do you have a Scope of Work document? (y/n): " sow
check_exit "$sow"

read -p "Do you have an NDA signed? (y/n): " nda
check_exit "$nda"

echo "[+] All authorization documents confirmed."
pause

######################
#   Scope Selection  #
######################

while true; do
  clear
  echo ">>> Step 2: Define Target Scope"
  echo "Select target type:"
  echo "  1) Public IP"
  echo "  2) IP Range"
  echo "  3) Subnet (CIDR, e.g. 192.168.1.0/24)"
  echo "  4) Domain name"
  echo "  5) Back"
  echo "  0) Exit"
  echo

  read -p "Enter your choice: " scope_choice

  case $scope_choice in
    1) read -p "Enter Public IP: " target;;
    2) read -p "Enter IP Range (e.g. 192.168.1.1-192.168.1.50): " target;;
    3) read -p "Enter Subnet (CIDR, e.g. 192.168.1.0/24): " target;;
    4) read -p "Enter Domain (e.g. example.com): " target;;
    5) continue;;
    0) echo "Exiting..."; exit 0;;
    *) echo "Invalid option"; pause; continue;;
  esac
  safe_target=$(sanitize_filename "$target")
  break
done

######################
#   Recon Menu       #
######################

while true; do
  clear
  echo ">>> Step 3: Reconnaissance Menu"
  echo "Target: $target"
  echo
  echo "Choose activity:"
  echo "  1) Passive Recon"
  echo "  2) DNS Enumeration"
  echo "  3) Network Discovery (Hosts/Ports)"
  echo "  4) Service Fingerprinting"
  echo "  5) Vulnerability Enumeration"
  echo "  9) Back to Scope Selection"
  echo "  0) Exit"
  echo

  read -p "Enter choice: " action_choice

  case $action_choice in
    1)
      clear
      echo "Passive Recon Options:"
      echo "  1) Subfinder"
      echo "  2) Amass"
      echo "  3) TheHarvester"
      echo "  9) Back"
      echo "  0) Exit"
      read -p "Choice: " passive_choice
      case $passive_choice in
        1) ensure_tool "subfinder" "sudo apt install -y subfinder"
           out="subfinder_$safe_target.txt"
           cmd="sudo subfinder -d $target -silent -o $out"
           log_command "subfinder" "$cmd" "$out"
           eval "$cmd" ;;
        2) ensure_tool "amass" "sudo apt install -y amass"
           out="amass_$safe_target.txt"
           cmd="sudo amass enum -passive -d $target -o $out"
           log_command "amass" "$cmd" "$out"
           eval "$cmd" ;;
        3) ensure_tool "theHarvester" "sudo apt install -y theharvester"
           out="harvester_$safe_target.html"
           cmd="sudo theHarvester -d $target -b all -l 500 -f $out"
           log_command "theHarvester" "$cmd" "$out"
           eval "$cmd" ;;
        9) continue ;;
        0) exit 0 ;;
        *) echo "Invalid option";;
      esac
      pause
      ;;
    4)
      clear
      echo "Service Fingerprinting Options:"
      echo "  1) nmap"
      echo "  2) httpx"
      echo "  3) sslscan"
      echo "  9) Back"
      echo "  0) Exit"
      read -p "Choice: " svc_choice
      case $svc_choice in
        1) ensure_tool "nmap" "sudo apt install -y nmap"
           out="nmap_$safe_target"
           cmd="sudo nmap -sV -T3 -Pn $target -oA $out"
           log_command "nmap" "$cmd" "$out.*"
           eval "$cmd" ;;
        2) ensure_tool "httpx" "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
           out="httpx_$safe_target.txt"
           cmd="echo $target | sudo httpx -silent -title -status-code -o $out"
           log_command "httpx" "$cmd" "$out"
           eval "$cmd" ;;
        3) ensure_tool "sslscan" "sudo apt install -y sslscan"
           out="sslscan_$safe_target.txt"
           cmd="sudo sslscan $target > $out"
           log_command "sslscan" "$cmd" "$out"
           eval "$cmd" ;;
        9) continue ;;
        0) exit 0 ;;
        *) echo "Invalid option";;
      esac
      pause
      ;;
    9) exec "$0" ;; # restart script to scope selection
    0) echo "Exiting..."; exit 0 ;;
    *) echo "Invalid option"; pause ;;
  esac
done
