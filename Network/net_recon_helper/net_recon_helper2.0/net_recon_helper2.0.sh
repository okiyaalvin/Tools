#!/usr/bin/env bash
# net_recon_helper2.0.sh
# OpenBash Pentesting Tools - Network Recon Helper
# Version: 2.0
# - Enforced RoE (strict y/n)
# - Evidence folder: Evidence/<target>/<YYYY-MM-DD>/ with 'latest' symlink
# - Logging to logs/net_recon_YYYYMMDD-HHMMSS.log
# - sudo-run for tools
# - Tool presence check + installer prompt (Enter = default install command, or custom)
# - RustScan installer using the provided .deb.zip method (2.4.1)
# - Complete menus: Passive, DNS, Network Discovery, Service Fingerprinting, Vulnerability Enumeration, Auth checks

set -euo pipefail
IFS=$'\n\t'

########## CONFIG ##########
LOG_DIR="logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/net_recon_$(date +%Y%m%d-%H%M%S).log"
########## HELPERS ##########

pause(){ read -n1 -rsp $'Press any key to continue...\n'; }

timestamp(){ date '+%Y-%m-%d %H:%M:%S'; }

# robust yes/no prompt (returns 'y' or 'n' on stdout)
ask_yesno(){
  local prompt="$1"
  local ans
  while true; do
    read -rp "$prompt (y/n): " ans
    ans="${ans,,}"
    if [[ "$ans" == "y" || "$ans" == "n" ]]; then
      printf '%s' "$ans"
      return 0
    fi
    echo "Please answer with 'y' or 'n'."
  done
}

sanitize_filename(){ printf '%s' "$1" | tr '/:' '_' ; }

log_line(){ echo "[$(timestamp)] $*" | tee -a "$LOG_FILE"; }

# generic ensure_tool (prompt to install if missing)
ensure_tool(){
  local tool="$1"; shift
  local default_install_cmd="$*"

  if command -v "$tool" &>/dev/null; then
    return 0
  fi

  echo "[-] Tool '$tool' not found."
  printf "Press Enter to install with default command [%s], or type custom command and press Enter: " "$default_install_cmd"
  read -r user_cmd
  if [[ -z "$user_cmd" ]]; then
    echo "[*] Installing with: $default_install_cmd"
    eval "$default_install_cmd"
  else
    echo "[*] Running custom install: $user_cmd"
    eval "$user_cmd"
  fi

  if ! command -v "$tool" &>/dev/null; then
    echo "[-] '$tool' still unavailable after install attempt." | tee -a "$LOG_FILE"
    return 1
  fi
  return 0
}

# rustscan installer using your working method (2.4.1 .deb.zip)
ensure_rustscan(){
  if command -v rustscan &>/dev/null; then return 0; fi

  echo "[-] rustscan not found. Attempt installation."
  printf "Press Enter to use default installer (GitHub 2.4.1 .deb.zip), or type custom command: "
  read -r user_cmd

  if [[ -n "$user_cmd" ]]; then
    eval "$user_cmd"
    command -v rustscan &>/dev/null && return 0 || echo "Custom install did not make rustscan available."
  else
    echo "[*] Downloading rustscan 2.4.1 .deb.zip..."
    wget -q -O /tmp/rustscan.deb.zip "https://github.com/bee-san/RustScan/releases/download/2.4.1/rustscan.deb.zip" || {
      echo "[-] Failed to download rustscan .deb.zip from GitHub." | tee -a "$LOG_FILE"
    }

    echo "[*] Extracting..."
    unzip -o /tmp/rustscan.deb.zip -d /tmp/ >/dev/null 2>&1 || {
      echo "[-] unzip failed or not present; try installing unzip or provide a custom command." | tee -a "$LOG_FILE"
    }

    if [[ -f /tmp/rustscan_2.4.1-1_amd64.deb ]]; then
      echo "[*] Installing RustScan .deb..."
      sudo dpkg -i /tmp/rustscan_2.4.1-1_amd64.deb || true
      echo "[*] Fixing dependencies..."
      sudo apt --fix-broken install -y || true
    else
      echo "[-] Expected deb not found after extraction." | tee -a "$LOG_FILE"
    fi

    # cleanup temp files we created (keep until we verify)
    rm -f /tmp/rustscan.deb.zip /tmp/rustscan_2.4.1-1_amd64.deb 2>/dev/null || true
  fi

  if command -v rustscan &>/dev/null; then
    echo "[✓] RustScan installed."
    return 0
  fi
  echo "[-] RustScan installation attempts failed." | tee -a "$LOG_FILE"
  return 1
}

# run and log a command (string). We log command and output path.
run_and_log(){
  local tool="$1"; local cmd="$2"; local out="$3"
  log_line "Target: $TARGET_RAW | Tool: $tool | Cmd: $cmd | Out: $out"
  eval "$cmd"
}

########## START ##########
echo "=== OpenBash Pentesting Tools - net_recon_helper v2.0 ===" | tee -a "$LOG_FILE"
log_line "Start: $(timestamp)"
log_line "Log file: $LOG_FILE"
echo "" >> "$LOG_FILE"

# DISCLAIMER
clear
cat <<'EOF'
==================================================================
  OpenBash Pentesting Tools - Network Recon Helper v2.0
==================================================================
[!] DISCLAIMER: Scanning, accessing or attacking systems without explicit,
    written authorization from the asset owner is illegal.
    Use this tool only for authorized VAPT engagements.
==================================================================
EOF
pause

# PRE-ENGAGEMENT CHECKLIST (strict y/n)
echo ">>> Pre-engagement checklist (ALL required). Responses will be logged."
required_docs=(
  "Signed Rules of Engagement (RoE)"
  "Signed Client Consent"
  "Approved target list (IPs/CIDRs/domains)"
  "Approved test windows"
  "Backup/snapshot confirmation for critical systems"
  "Emergency contact list (phone/email)"
)
for doc in "${required_docs[@]}"; do
  while true; do
    resp=$(ask_yesno "Do you have: $doc ?")
    if [[ "$resp" == "y" ]]; then
      log_line "ROE: OK - $doc"
      break
    elif [[ "$resp" == "n" ]]; then
      log_line "ROE: MISSING - $doc"
      echo "Missing required item: $doc. You are not authorized to proceed."
      pause
      exit 1
    fi
  done
done
echo "[+] Pre-engagement checklist confirmed." | tee -a "$LOG_FILE"
pause

# SCOPE selection
while true; do
  clear
  cat <<'EOF'
Step: Define target scope (Public IP / Private IP / Range / Subnet / Domain)
  1) Single IP (public or private)
  2) IP Range (start-end)
  3) Subnet CIDR (e.g., 10.0.0.0/24)
  4) Domain (example.com)
  5) Exit
EOF
  read -rp "Select [1-5]: " sc
  case "$sc" in
    1) read -rp "Enter IP (public or private): " TARGET_RAW; break ;;
    2) read -rp "Enter IP range (start-end): " TARGET_RAW; break ;;
    3) read -rp "Enter CIDR (e.g., 10.0.0.0/24): " TARGET_RAW; break ;;
    4) read -rp "Enter domain (example.com): " TARGET_RAW; break ;;
    5) echo "Exiting..."; exit 0 ;;
    *) echo "Invalid choice."; pause ;;
  esac
done

SAFE_TARGET=$(sanitize_filename "$TARGET_RAW")
EVIDENCE_DIR="Evidence/${SAFE_TARGET}/$(date +%Y-%m-%d)"
mkdir -p "$EVIDENCE_DIR"
# create/update latest symlink in Evidence/<target>/
ln -sfn "$(basename "$EVIDENCE_DIR")" "$(dirname "$EVIDENCE_DIR")/latest" 2>/dev/null || true

log_line "Target: $TARGET_RAW"
log_line "Evidence path: $EVIDENCE_DIR"
echo "" >> "$LOG_FILE"
pause

########## SUBMENUS ##########

passive_recon(){
  while true; do
    clear
    cat <<EOF
Passive Recon (target: $TARGET_RAW)
  1) subfinder (passive)
  2) amass (passive)
  3) theHarvester
  9) Back
  0) Exit
EOF
    read -rp "Choice: " c
    case "$c" in
      1)
        ensure_tool subfinder "sudo apt update && sudo apt install -y subfinder || true"
        OUT="$EVIDENCE_DIR/subfinder_${SAFE_TARGET}.txt"
        CMD="sudo subfinder -d \"$TARGET_RAW\" -silent -o \"$OUT\""
        run_and_log "subfinder" "$CMD" "$OUT"
        ;;
      2)
        ensure_tool amass "sudo apt update && sudo apt install -y amass || true"
        OUT="$EVIDENCE_DIR/amass_${SAFE_TARGET}.txt"
        CMD="sudo amass enum -passive -d \"$TARGET_RAW\" -o \"$OUT\""
        run_and_log "amass" "$CMD" "$OUT"
        ;;
      3)
        ensure_tool theHarvester "sudo apt update && sudo apt install -y theharvester || true"
        OUT="$EVIDENCE_DIR/theHarvester_${SAFE_TARGET}.html"
        CMD="sudo theHarvester -d \"$TARGET_RAW\" -b all -l 500 -f \"$OUT\""
        run_and_log "theHarvester" "$CMD" "$OUT"
        ;;
      9) return ;;
      0) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid option"; pause ;;
    esac
    pause
  done
}

dns_enum(){
  while true; do
    clear
    cat <<EOF
DNS & Name Resolution (target: $TARGET_RAW)
  1) dnsrecon (records + AXFR)
  2) massdns (validate wordlist)
  3) dig (manual)
  4) sublist3r (bruteforce)
  9) Back
  0) Exit
EOF
    read -rp "Choice: " c
    case "$c" in
      1)
        ensure_tool dnsrecon "sudo apt update && sudo apt install -y dnsrecon || true"
        OUT="$EVIDENCE_DIR/dnsrecon_${SAFE_TARGET}.txt"
        CMD="sudo dnsrecon -d \"$TARGET_RAW\" -t std -a -o \"$OUT\""
        run_and_log "dnsrecon" "$CMD" "$OUT"
        ;;
      2)
        ensure_tool massdns "sudo apt update && sudo apt install -y massdns || true"
        read -rp "Path to subdomain wordlist: " WL
        if [[ ! -f "$WL" ]]; then echo "Wordlist not found"; pause; continue; fi
        OUT="$EVIDENCE_DIR/massdns_${SAFE_TARGET}.txt"
        RESOLVERS="/etc/resolv.conf"
        CMD="sudo massdns -r \"$RESOLVERS\" -t A -o S -w \"$OUT\" \"$WL\""
        run_and_log "massdns" "$CMD" "$OUT"
        ;;
      3)
        read -rp "dig query (default: ANY $TARGET_RAW): " DQ
        DQ=${DQ:-"ANY $TARGET_RAW"}
        OUT="$EVIDENCE_DIR/dig_${SAFE_TARGET}.txt"
        log_line "dig query: $DQ"
        dig $DQ +noall +answer | tee "$OUT"
        ;;
      4)
        ensure_tool sublist3r "sudo apt update && sudo apt install -y sublist3r || true"
        OUT="$EVIDENCE_DIR/sublist3r_${SAFE_TARGET}.txt"
        CMD="sudo sublist3r -d \"$TARGET_RAW\" -o \"$OUT\""
        run_and_log "sublist3r" "$CMD" "$OUT"
        ;;
      9) return ;;
      0) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid option"; pause ;;
    esac
    pause
  done
}

network_discovery(){
  while true; do
    clear
    cat <<EOF
Network Discovery (fast host/port discovery)
  1) masscan (fast port sweep)
  2) naabu (fast discovery)
  3) fping (ICMP sweep)
  4) rustscan (quick + nmap)
  9) Back
  0) Exit
EOF
    read -rp "Choice: " c
    case "$c" in
      1)
        ensure_tool masscan "sudo apt update && sudo apt install -y masscan || true"
        read -rp "Ports (default 1-65535): " PTS; PTS=${PTS:-1-65535}
        read -rp "Rate (pps, conservative default 500): " RATE; RATE=${RATE:-500}
        OUT="$EVIDENCE_DIR/masscan_${SAFE_TARGET}.txt"
        CMD="sudo masscan \"$TARGET_RAW\" -p$PTS --rate $RATE -oL \"$OUT\""
        run_and_log "masscan" "$CMD" "$OUT"
        ;;
      2)
        ensure_tool naabu "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true"
        OUT="$EVIDENCE_DIR/naabu_${SAFE_TARGET}.txt"
        CMD="echo \"$TARGET_RAW\" | sudo naabu -rate 100 -o \"$OUT\""
        run_and_log "naabu" "$CMD" "$OUT"
        ;;
      3)
        ensure_tool fping "sudo apt update && sudo apt install -y fping || true"
        OUT="$EVIDENCE_DIR/fping_${SAFE_TARGET}.txt"
        CMD="sudo fping -a -g \"$TARGET_RAW\" 2>/dev/null > \"$OUT\" || true"
        run_and_log "fping" "$CMD" "$OUT"
        ;;
      4)
        if ! ensure_rustscan; then
          echo "rustscan not available; returning to menu." | tee -a "$LOG_FILE"
          pause
          continue
        fi
        OUT_PREFIX="$EVIDENCE_DIR/rustscan_${SAFE_TARGET}"
        CMD="sudo rustscan -a \"$TARGET_RAW\" --ulimit 5000 -b 500 -- -sV -A -oA \"$OUT_PREFIX\""
        run_and_log "rustscan" "$CMD" "$OUT_PREFIX.*"
        ;;
      9) return ;;
      0) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid option"; pause ;;
    esac
    pause
  done
}

service_fingerprinting(){
  while true; do
    clear
    cat <<EOF
Service Fingerprinting (detailed)
  1) nmap (sV, scripts safe)
  2) httpx (HTTP probing)
  3) sslscan / testssl.sh
  9) Back
  0) Exit
EOF
    read -rp "Choice: " c
    case "$c" in
      1)
        ensure_tool nmap "sudo apt update && sudo apt install -y nmap || true"
        read -rp "Ports (default 1-65535): " PTS; PTS=${PTS:-"1-65535"}
        OUT_PREFIX="$EVIDENCE_DIR/nmap_${SAFE_TARGET}"
        CMD="sudo nmap -sS -sV -p $PTS -T3 --script 'default,safe' \"$TARGET_RAW\" -oA \"$OUT_PREFIX\""
        run_and_log "nmap" "$CMD" "$OUT_PREFIX.*"
        ;;
      2)
        ensure_tool httpx "go install github.com/projectdiscovery/httpx/cmd/httpx@latest || true"
        OUT="$EVIDENCE_DIR/httpx_${SAFE_TARGET}.txt"
        CMD="echo \"$TARGET_RAW\" | sudo httpx -silent -title -status-code -o \"$OUT\""
        run_and_log "httpx" "$CMD" "$OUT"
        ;;
      3)
        if command -v sslscan &>/dev/null; then
          OUT="$EVIDENCE_DIR/sslscan_${SAFE_TARGET}.txt"
          CMD="sudo sslscan \"$TARGET_RAW\" > \"$OUT\""
          run_and_log "sslscan" "$CMD" "$OUT"
        elif [[ -f "./testssl.sh" ]]; then
          OUT="$EVIDENCE_DIR/testssl_${SAFE_TARGET}.txt"
          CMD="sudo ./testssl.sh --fast \"$TARGET_RAW\" | tee \"$OUT\""
          run_and_log "testssl.sh" "$CMD" "$OUT"
        else
          echo "sslscan/testssl.sh not available." | tee -a "$LOG_FILE"
        fi
        ;;
      9) return ;;
      0) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid option"; pause ;;
    esac
    pause
  done
}

vuln_enum(){
  while true; do
    clear
    cat <<EOF
Lightweight Vulnerability Enumeration (non-destructive)
  1) nmap (vuln NSE scripts)
  2) nikto (webserver)
  3) nuclei (templates)
  9) Back
  0) Exit
EOF
    read -rp "Choice: " c
    case "$c" in
      1)
        ensure_tool nmap "sudo apt update && sudo apt install -y nmap || true"
        OUT_PREFIX="$EVIDENCE_DIR/nmap_vuln_${SAFE_TARGET}"
        CMD="sudo nmap --script vuln -sV -p 1-65535 \"$TARGET_RAW\" -oA \"$OUT_PREFIX\""
        run_and_log "nmap-vuln" "$CMD" "$OUT_PREFIX.*"
        ;;
      2)
        ensure_tool nikto "sudo apt update && sudo apt install -y nikto || true"
        read -rp "Target URL (default: https://$TARGET_RAW): " TURL
        TURL=${TURL:-"https://$TARGET_RAW"}
        OUT="$EVIDENCE_DIR/nikto_${SAFE_TARGET}.txt"
        CMD="sudo nikto -h \"$TURL\" -o \"$OUT\""
        run_and_log "nikto" "$CMD" "$OUT"
        ;;
      3)
        ensure_tool nuclei "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest || true"
        read -rp "Targets file (leave empty to use single target): " TFILE
        OUT="$EVIDENCE_DIR/nuclei_${SAFE_TARGET}.txt"
        if [[ -n "$TFILE" && -f "$TFILE" ]]; then
          CMD="sudo nuclei -l \"$TFILE\" -rate 25 -o \"$OUT\""
        else
          echo "$TARGET_RAW" > "$EVIDENCE_DIR/_tmp_targets.txt"
          CMD="sudo nuclei -l \"$EVIDENCE_DIR/_tmp_targets.txt\" -rate 25 -o \"$OUT\""
        fi
        run_and_log "nuclei" "$CMD" "$OUT"
        rm -f "$EVIDENCE_DIR/_tmp_targets.txt" 2>/dev/null || true
        ;;
      9) return ;;
      0) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid option"; pause ;;
    esac
    pause
  done
}

auth_checks(){
  while true; do
    clear
    cat <<EOF
Credential & Authentication Discovery (non-destructive; only if authorized)
  1) SMB anonymous (smbclient / enum4linux)
  2) SNMP public check (snmpwalk)
  3) SMTP banner / VRFY (nc)
  9) Back
  0) Exit
EOF
    read -rp "Choice: " c
    case "$c" in
      1)
        # smbclient / enum4linux
        if ! command -v smbclient &>/dev/null; then
          ensure_tool smbclient "sudo apt update && sudo apt install -y smbclient || true"
        fi
        OUT="$EVIDENCE_DIR/smb_${SAFE_TARGET}.txt"
        CMD="sudo smbclient -L //$TARGET_RAW -N 2>&1 | tee \"$OUT\" || true"
        run_and_log "smbclient" "$CMD" "$OUT"
        if command -v enum4linux &>/dev/null; then
          OUT2="$EVIDENCE_DIR/enum4linux_${SAFE_TARGET}.txt"
          CMD2="sudo enum4linux -a \"$TARGET_RAW\" | tee \"$OUT2\""
          run_and_log "enum4linux" "$CMD2" "$OUT2"
        fi
        ;;
      2)
        ensure_tool snmpwalk "sudo apt update && sudo apt install -y snmp || true"
        read -rp "SNMP community (default 'public'): " COMM; COMM=${COMM:-public}
        OUT="$EVIDENCE_DIR/snmpwalk_${SAFE_TARGET}.txt"
        CMD="sudo snmpwalk -v2c -c \"$COMM\" \"$TARGET_RAW\" | tee \"$OUT\" || true"
        run_and_log "snmpwalk" "$CMD" "$OUT"
        ;;
      3)
        ensure_tool nc "sudo apt update && sudo apt install -y netcat || true"
        OUT="$EVIDENCE_DIR/smtp_banner_${SAFE_TARGET}.txt"
        CMD="(echo QUIT) | sudo nc -w 3 \"$TARGET_RAW\" 25 2>/dev/null | tee \"$OUT\" || true"
        run_and_log "nc" "$CMD" "$OUT"
        echo "If VRFY allowed, example: echo -e \"VRFY postmaster\" | nc $TARGET_RAW 25"
        ;;
      9) return ;;
      0) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid option"; pause ;;
    esac
    pause
  done
}

########## MAIN MENU ##########
while true; do
  clear
  cat <<EOF
Reconnaissance Menu
Target: $TARGET_RAW
Evidence Path: $EVIDENCE_DIR

  1) Passive Recon
  2) DNS Enumeration
  3) Network Discovery (Hosts/Ports)
  4) Service Fingerprinting
  5) Vulnerability Enumeration
  6) Credential & Auth checks (non-destructive)
  9) Back (change target / restart)
  0) Exit
EOF
  read -rp "Enter choice: " choice
  case "$choice" in
    1) passive_recon ;;
    2) dns_enum ;;
    3) network_discovery ;;
    4) service_fingerprinting ;;
    5) vuln_enum ;;
    6) auth_checks ;;
    9) exec "$0" ;; # restart script (back to top)
    0) echo "Exiting..."; exit 0 ;;
    *) echo "Invalid option"; pause ;;
  esac
done
