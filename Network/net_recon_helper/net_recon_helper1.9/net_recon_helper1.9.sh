#!/bin/bash
# net_recon_helper1.9.sh
# OpenBash Pentesting Tools - Network Recon Helper
# Author: Your Pentest Team
# Disclaimer: For authorized security testing only.
# Version: 1.9 - improved RoE y/n validation

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

# New: robust yes/no prompt that only accepts 'y' or 'n' (case-insensitive)
ask_yesno(){
  local prompt="$1"
  local ans
  while true; do
    read -rp "$prompt (y/n): " ans
    ans="${ans,,}"   # to lowercase
    if [[ "$ans" == "y" || "$ans" == "n" ]]; then
      printf '%s' "$ans"
      return 0
    else
      echo "Please answer with 'y' or 'n'."
    fi
  done
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

# special installer for rustscan (v2.4.1 method from Revoltcipher)
ensure_rustscan(){
  if command -v rustscan &>/dev/null; then return 0; fi

  echo "[-] rustscan not found. Attempt installation."
  printf "Press Enter to use default installer (GitHub 2.4.1 .deb.zip), or type custom command: "
  read -r user_cmd

  if [[ -n "$user_cmd" ]]; then
    eval "$user_cmd"
    command -v rustscan &>/dev/null && return 0 || echo "Custom install failed."
  else
    echo "[*] Downloading rustscan 2.4.1 .deb.zip..."
    wget -O /tmp/rustscan.deb.zip https://github.com/bee-san/RustScan/releases/download/2.4.1/rustscan.deb.zip

    echo "[*] Extracting..."
    unzip -o /tmp/rustscan.deb.zip -d /tmp/

    echo "[*] Installing RustScan..."
    sudo dpkg -i /tmp/rustscan_2.4.1-1_amd64.deb || true

    echo "[*] Fixing dependencies..."
    sudo apt --fix-broken install -y || true

    rm -f /tmp/rustscan.deb.zip /tmp/rustscan_2.4.1-1_amd64.deb 2>/dev/null || true
  fi

  if command -v rustscan &>/dev/null; then
    echo "[✓] RustScan installation complete."
    return 0
  else
    echo "[-] RustScan install failed. Please install manually."
    return 1
  fi
}

######################
#      Disclaimer    #
######################

clear
echo "=============================================================="
echo "   OpenBash Pentesting Tools - Network Recon Helper v1.9"
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

# Use the robust ask_yesno function for validation
resp=$(ask_yesno "Do you have a signed Rules of Engagement?")
if [[ "$resp" == "n" ]]; then check_exit "n"; fi
echo "Rules of Engagement: $resp" >> "$LOG_FILE"

resp=$(ask_yesno "Do you have a signed Client Consent?")
if [[ "$resp" == "n" ]]; then check_exit "n"; fi
echo "Client Consent: $resp" >> "$LOG_FILE"

resp=$(ask_yesno "Do you have a Scope of Work document?")
if [[ "$resp" == "n" ]]; then check_exit "n"; fi
echo "Scope of Work: $resp" >> "$LOG_FILE"

resp=$(ask_yesno "Do you have an NDA signed?")
if [[ "$resp" == "n" ]]; then check_exit "n"; fi
echo "NDA: $resp" >> "$LOG_FILE"

echo "[+] All authorization documents confirmed."
pause

######################
#   Scope Selection  #
######################

while true; do
  clear
  echo ">>> Step 2: Define Target Scope"
  echo "Select target type:"
  echo "  1) Public/Private IP"
  echo "  2) IP Range"
  echo "  3) Subnet (CIDR, e.g. 192.168.1.0/24)"
  echo "  4) Domain name"
  echo "  5) Back"
  echo "  0) Exit"
  echo

  read -p "Enter your choice: " scope_choice

  case $scope_choice in
    1) read -p "Enter IP: " target;;
    2) read -p "Enter IP Range (e.g. 192.168.1.1-192.168.1.50): " target;;
    3) read -p "Enter Subnet (CIDR, e.g. 192.168.1.0/24): " target;;
    4) read -p "Enter Domain (e.g. example.com): " target;;
    5) continue;;
    0) echo "Exiting..."; exit 0;;
    *) echo "Invalid option"; pause; continue;;
  esac
  safe_target=$(sanitize_filename "$target")
  EVIDENCE_DIR="Evidence/${safe_target}/$(date +%Y-%m-%d)"
  mkdir -p "$EVIDENCE_DIR"
  echo "[*] Evidence will be stored in: $EVIDENCE_DIR"
  pause
  break
done

######################
#   Recon Menu       #
######################

while true; do
  clear
  echo ">>> Step 3: Reconnaissance Menu"
  echo "Target: $target"
  echo "Evidence Path: $EVIDENCE_DIR"
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
           out="$EVIDENCE_DIR/subfinder_$safe_target.txt"
           cmd="sudo subfinder -d $target -silent -o $out"
           log_command "subfinder" "$cmd" "$out"
           eval "$cmd" ;;
        2) ensure_tool "amass" "sudo apt install -y amass"
           out="$EVIDENCE_DIR/amass_$safe_target.txt"
           cmd="sudo amass enum -passive -d $target -o $out"
           log_command "amass" "$cmd" "$out"
           eval "$cmd" ;;
        3) ensure_tool "theHarvester" "sudo apt install -y theharvester"
           out="$EVIDENCE_DIR/harvester_$safe_target.html"
           cmd="sudo theHarvester -d $target -b all -l 500 -f $out"
           log_command "theHarvester" "$cmd" "$out"
           eval "$cmd" ;;
        9) continue ;;
        0) exit 0 ;;
        *) echo "Invalid option";;
      esac
      pause
      ;;
    3)
      clear
      echo "Network Discovery (fast host/port discovery)"
      echo "  1) masscan (fast port sweep)"
      echo "  2) naabu (fast discovery)"
      echo "  3) fping (ICMP sweep)"
      echo "  4) RustScan (quick + nmap)"
      echo "  9) Back"
      echo "  0) Exit"
      read -p "Choice: " net_choice
      case $net_choice in
        1) ensure_tool "masscan" "sudo apt install -y masscan"
           out="$EVIDENCE_DIR/masscan_$safe_target.txt"
           cmd="sudo masscan -p1-65535 $target --rate=1000 -oL $out"
           log_command "masscan" "$cmd" "$out"
           eval "$cmd" ;;
        2) ensure_tool "naabu" "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
           out="$EVIDENCE_DIR/naabu_$safe_target.txt"
           cmd="echo $target | sudo naabu -rate 1000 -o $out"
           log_command "naabu" "$cmd" "$out"
           eval "$cmd" ;;
        3) ensure_tool "fping" "sudo apt install -y fping"
           out="$EVIDENCE_DIR/fping_$safe_target.txt"
           cmd="sudo fping -a -g $target 2>/dev/null | tee $out"
           log_command "fping" "$cmd" "$out"
           eval "$cmd" ;;
        4) ensure_rustscan
           out="$EVIDENCE_DIR/rustscan_$safe_target"
           cmd="sudo rustscan -a \"$target\" --ulimit 5000 -b 500 -- -sV -A -oA $out"
           log_command "rustscan" "$cmd" "$out.*"
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
           out="$EVIDENCE_DIR/nmap_$safe_target"
           cmd="sudo nmap -sV -T3 -Pn $target -oA $out"
           log_command "nmap" "$cmd" "$out.*"
           eval "$cmd" ;;
        2) ensure_tool "httpx" "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
           out="$EVIDENCE_DIR/httpx_$safe_target.txt"
           cmd="echo $target | sudo httpx -silent -title -status-code -o $out"
           log_command "httpx" "$cmd" "$out"
           eval "$cmd" ;;
        3) ensure_tool "sslscan" "sudo apt install -y sslscan"
           out="$EVIDENCE_DIR/sslscan_$safe_target.txt"
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
