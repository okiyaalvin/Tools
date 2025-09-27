#!/usr/bin/env bash
# net_recon_helper1.6.sh
# OpenBash Pentesting Tools - Network Recon Helper
# Version: 1.6
# Keeps: disclaimer, RoE, evidence folder, sudo-run, tool install prompts, logging
set -euo pipefail
IFS=$'\n\t'

# Directories
LOG_DIR="logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/net_recon_$(date +%Y%m%d-%H%M%S).log"

# Helpers
pause(){ read -n1 -rsp $'Press any key to continue...\n'; }
sanitize_filename(){ printf '%s' "$1" | tr '/:' '_'; }
check_yesno(){ [[ "${1,,}" == "y" ]]; }
timestamp(){ date '+%Y-%m-%d %H:%M:%S'; }

# Ensure tool exists, offer install (Enter = default install cmd, or custom)
ensure_tool(){
  local tool="$1"; shift
  local default_install="$*"
  if ! command -v "$tool" &>/dev/null; then
    echo "[-] Tool '$tool' not found."
    printf "Press Enter to install with default command [%s], or type custom command: " "$default_install"
    read -r user_cmd
    if [[ -z "$user_cmd" ]]; then
      echo "[*] Installing with: $default_install"
      eval "$default_install"
    else
      echo "[*] Running custom install: $user_cmd"
      eval "$user_cmd"
    fi
  fi
}

log_command(){
  local tool="$1"; local cmd="$2"; local out="$3"
  echo "[$(timestamp)] Target: $TARGET_RAW | Tool: $tool | Command: $cmd | Output: $out" | tee -a "$LOG_FILE"
}

run_cmd_and_log(){
  # run command (string) with sudo, log with tool and output path
  local tool="$1"; local cmd="$2"; local out="$3"
  log_command "$tool" "$cmd" "$out"
  eval "$cmd"
}

# Start - disclaimer
clear
cat <<'EOF'
==============================================================
  OpenBash Pentesting Tools - Network Recon Helper v1.6
==============================================================
[!] DISCLAIMER: Scanning or accessing systems without explicit,
    written authorization from the asset owner is illegal.
    Use this tool only for authorized VAPT engagements.
==============================================================
EOF
pause

# RoE & checklist enforcement
echo ">>> Pre-engagement checklist (all items required)"
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
    read -rp "Do you have: $doc ? (y/n): " resp
    resp="${resp,,}"
    if [[ "$resp" == "y" ]]; then
      echo "OK: $doc" >> "$LOG_FILE"
      break
    elif [[ "$resp" == "n" ]]; then
      echo "Missing required item: $doc. Exiting." | tee -a "$LOG_FILE"
      pause
      exit 1
    else
      echo "Please answer y or n."
    fi
  done
done
echo "[+] All checklist items confirmed." | tee -a "$LOG_FILE"
pause

# Scope selection
while true; do
  clear
  cat <<'EOF'
Step 1: Define target scope
(choose Public IP / Private IP / Range / Subnet / Domain)
  1) Single IP (Public or Private)
  2) IP Range (e.g., 192.168.1.1-192.168.1.50)
  3) Subnet CIDR (e.g., 192.168.1.0/24)
  4) Domain (e.g., example.com)
  5) Exit
EOF
  read -rp "Select [1-5]: " sc
  case "$sc" in
    1) read -rp "Enter IP (public or private): " TARGET_RAW; break ;;
    2) read -rp "Enter IP range (start-end): " TARGET_RAW; break ;;
    3) read -rp "Enter CIDR (e.g., 10.0.0.0/24): " TARGET_RAW; break ;;
    4) read -rp "Enter domain (example.com): " TARGET_RAW; break ;;
    5) echo "Exiting..."; exit 0 ;;
    *) echo "Invalid choice." ; pause ;;
  esac
done

SAFE_TARGET=$(sanitize_filename "$TARGET_RAW")
EVIDENCE_DIR="Evidence/${SAFE_TARGET}/$(date +%Y-%m-%d)"
mkdir -p "$EVIDENCE_DIR"
# create/update latest symlink
ln -sfn "$(basename "$EVIDENCE_DIR")" "$(dirname "$EVIDENCE_DIR")/latest" 2>/dev/null || true

echo "[*] Evidence path: $EVIDENCE_DIR" | tee -a "$LOG_FILE"
pause

# Common submenu handlers
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
        ensure_tool subfinder "sudo apt-get update && sudo apt-get install -y subfinder || true"
        OUT="$EVIDENCE_DIR/subfinder_${SAFE_TARGET}.txt"
        CMD="sudo subfinder -d $TARGET_RAW -silent -o $OUT"
        run_cmd_and_log "subfinder" "$CMD" "$OUT"
        ;;
      2)
        ensure_tool amass "sudo apt-get update && sudo apt-get install -y amass || true"
        OUT="$EVIDENCE_DIR/amass_${SAFE_TARGET}.txt"
        CMD="sudo amass enum -passive -d $TARGET_RAW -o $OUT"
        run_cmd_and_log "amass" "$CMD" "$OUT"
        ;;
      3)
        ensure_tool theHarvester "sudo apt-get update && sudo apt-get install -y theharvester || true"
        OUT="$EVIDENCE_DIR/theharvester_${SAFE_TARGET}.html"
        CMD="sudo theHarvester -d $TARGET_RAW -b all -l 500 -f $OUT"
        run_cmd_and_log "theHarvester" "$CMD" "$OUT"
        ;;
      9) return ;;
      0) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid"; pause ;;
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
        ensure_tool dnsrecon "sudo apt-get update && sudo apt-get install -y dnsrecon || true"
        OUT="$EVIDENCE_DIR/dnsrecon_${SAFE_TARGET}.txt"
        CMD="sudo dnsrecon -d $TARGET_RAW -t std -a -o $OUT"
        run_cmd_and_log "dnsrecon" "$CMD" "$OUT"
        ;;
      2)
        ensure_tool massdns "sudo apt-get update && sudo apt-get install -y massdns || true"
        read -rp "Path to subdomain wordlist: " WL
        [[ -f "$WL" ]] || { echo "Wordlist not found"; pause; continue; }
        OUT="$EVIDENCE_DIR/massdns_${SAFE_TARGET}.txt"
        # resolvers file default - use /etc/resolv.conf as fallback, better to provide own
        RESOLVERS="/etc/resolv.conf"
        CMD="sudo massdns -r $RESOLVERS -t A -o S -w $OUT $WL"
        run_cmd_and_log "massdns" "$CMD" "$OUT"
        ;;
      3)
        read -rp "dig query (default: ANY $TARGET_RAW): " DQ
        DQ=${DQ:-"ANY $TARGET_RAW"}
        echo "Running: dig $DQ"; dig $DQ +noall +answer | tee "$EVIDENCE_DIR/dig_${SAFE_TARGET}.txt"
        ;;
      4)
        ensure_tool sublist3r "sudo apt-get update && sudo apt-get install -y sublist3r || true"
        OUT="$EVIDENCE_DIR/sublist3r_${SAFE_TARGET}.txt"
        CMD="sudo sublist3r -d $TARGET_RAW -o $OUT"
        run_cmd_and_log "sublist3r" "$CMD" "$OUT"
        ;;
      9) return ;;
      0) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid"; pause ;;
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
  4) RustScan (quick + nmap)
  9) Back
  0) Exit
EOF
    read -rp "Choice: " c
    case "$c" in
      1)
        ensure_tool masscan "sudo apt-get update && sudo apt-get install -y masscan || true"
        read -rp "Ports (default 1-65535): " PTS; PTS=${PTS:-1-65535}
        read -rp "Rate (pps, conservative default 500): " RATE; RATE=${RATE:-500}
        OUT="$EVIDENCE_DIR/masscan_${SAFE_TARGET}.txt"
        CMD="sudo masscan \"$TARGET_RAW\" -p$PTS --rate $RATE -oL $OUT"
        run_cmd_and_log "masscan" "$CMD" "$OUT"
        ;;
      2)
        ensure_tool naabu "sudo apt-get update && sudo apt-get install -y naabu || true"
        OUT="$EVIDENCE_DIR/naabu_${SAFE_TARGET}.txt"
        # naabu supports host or -list
        CMD="sudo naabu -host \"$TARGET_RAW\" -o $OUT"
        run_cmd_and_log "naabu" "$CMD" "$OUT"
        ;;
      3)
        ensure_tool fping "sudo apt-get update && sudo apt-get install -y fping || true"
        OUT="$EVIDENCE_DIR/fping_${SAFE_TARGET}.txt"
        CMD="sudo fping -a -g $TARGET_RAW 2>/dev/null > $OUT || true"
        run_cmd_and_log "fping" "$CMD" "$OUT"
        ;;
      4)
        ensure_tool rustscan "sudo apt-get update && sudo apt-get install -y rustscan || true"
        OUT_PREFIX="$EVIDENCE_DIR/rustscan_${SAFE_TARGET}"
        CMD="sudo rustscan -a \"$TARGET_RAW\" --ulimit 5000 -b 500 -- -sV -A -oA $OUT_PREFIX"
        run_cmd_and_log "rustscan" "$CMD" "$OUT_PREFIX.*"
        ;;
      9) return ;;
      0) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid"; pause ;;
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
        ensure_tool nmap "sudo apt-get update && sudo apt-get install -y nmap || true"
        read -rp "Ports (default top 1000): " PTS; PTS=${PTS:-"1-65535"}
        TIMING="T3"
        OUT_PREFIX="$EVIDENCE_DIR/nmap_${SAFE_TARGET}"
        CMD="sudo nmap -sS -sV -p $PTS -T3 --script 'default,safe' \"$TARGET_RAW\" -oA $OUT_PREFIX"
        run_cmd_and_log "nmap" "$CMD" "$OUT_PREFIX.*"
        ;;
      2)
        ensure_tool httpx "go install github.com/projectdiscovery/httpx/cmd/httpx@latest || true"
        OUT="$EVIDENCE_DIR/httpx_${SAFE_TARGET}.txt"
        CMD="echo \"$TARGET_RAW\" | sudo httpx -silent -title -status-code -o $OUT"
        run_cmd_and_log "httpx" "$CMD" "$OUT"
        ;;
      3)
        # try sslscan first, fallback to testssl
        if command -v sslscan &>/dev/null; then
          ensure_tool sslscan "sudo apt-get update && sudo apt-get install -y sslscan || true"
          OUT="$EVIDENCE_DIR/sslscan_${SAFE_TARGET}.txt"
          CMD="sudo sslscan \"$TARGET_RAW\" > $OUT"
          run_cmd_and_log "sslscan" "$CMD" "$OUT"
        elif [[ -f "./testssl.sh" ]]; then
          OUT="$EVIDENCE_DIR/testssl_${SAFE_TARGET}.txt"
          CMD="sudo ./testssl.sh --fast \"$TARGET_RAW\" | tee $OUT"
          run_cmd_and_log "testssl.sh" "$CMD" "$OUT"
        else
          echo "sslscan/testssl.sh not available."
          pause
        fi
        ;;
      9) return ;;
      0) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid"; pause ;;
    esac
    pause
  done
}

vuln_enum(){
  while true; do
    clear
    cat <<EOF
Lightweight Vulnerability Enumeration (non-destructive)
  1) nuclei (templates)
  2) nikto (webserver)
  3) nmap --script vuln
  9) Back
  0) Exit
EOF
    read -rp "Choice: " c
    case "$c" in
      1)
        ensure_tool nuclei "sudo apt-get update && sudo apt-get install -y nuclei || true"
        read -rp "Targets file (leave empty to use single target): " TFILE
        OUT="$EVIDENCE_DIR/nuclei_${SAFE_TARGET}.txt"
        if [[ -n "$TFILE" && -f "$TFILE" ]]; then
          CMD="sudo nuclei -l \"$TFILE\" -rate 25 -o $OUT"
        else
          echo "$TARGET_RAW" > "$EVIDENCE_DIR/_tmp_targets.txt"
          CMD="sudo nuclei -l \"$EVIDENCE_DIR/_tmp_targets.txt\" -rate 25 -o $OUT"
        fi
        run_cmd_and_log "nuclei" "$CMD" "$OUT"
        rm -f "$EVIDENCE_DIR/_tmp_targets.txt" 2>/dev/null || true
        ;;
      2)
        ensure_tool nikto "sudo apt-get update && sudo apt-get install -y nikto || true"
        read -rp "Target URL (default: https://$TARGET_RAW): " TURL
        TURL=${TURL:-"https://$TARGET_RAW"}
        OUT="$EVIDENCE_DIR/nikto_${SAFE_TARGET}.txt"
        CMD="sudo nikto -h \"$TURL\" -o $OUT"
        run_cmd_and_log "nikto" "$CMD" "$OUT"
        ;;
      3)
        ensure_tool nmap "sudo apt-get update && sudo apt-get install -y nmap || true"
        OUT_PREFIX="$EVIDENCE_DIR/nmap_vuln_${SAFE_TARGET}"
        CMD="sudo nmap --script vuln -sV -p 1-65535 \"$TARGET_RAW\" -oA $OUT_PREFIX"
        run_cmd_and_log "nmap_vuln" "$CMD" "$OUT_PREFIX.*"
        ;;
      9) return ;;
      0) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid"; pause ;;
    esac
    pause
  done
}

auth_checks(){
  while true; do
    clear
    cat <<EOF
Credential & Authentication Discovery (non-destructive, only if authorized)
  1) SMB anonymous (smbclient / enum4linux)
  2) SNMP public check (snmpwalk)
  3) SMTP banner / VRFY (nc)
  9) Back
  0) Exit
EOF
    read -rp "Choice: " c
    case "$c" in
      1)
        # smbclient/enum4linux
        if ! command -v smbclient &>/dev/null && ! command -v enum4linux &>/dev/null; then
          ensure_tool "smbclient/enum4linux" "sudo apt-get update && sudo apt-get install -y smbclient enum4linux || true"
        fi
        OUT="$EVIDENCE_DIR/smb_${SAFE_TARGET}.txt"
        CMD="sudo smbclient -L //$TARGET_RAW -N 2>&1 | tee $OUT || true"
        run_cmd_and_log "smbclient" "$CMD" "$OUT"
        if command -v enum4linux &>/dev/null; then
          OUT2="$EVIDENCE_DIR/enum4linux_${SAFE_TARGET}.txt"
          CMD2="sudo enum4linux -a $TARGET_RAW | tee $OUT2"
          run_cmd_and_log "enum4linux" "$CMD2" "$OUT2"
          eval "$CMD2"
        fi
        ;;
      2)
        ensure_tool snmpwalk "sudo apt-get update && sudo apt-get install -y snmp || true"
        read -rp "SNMP community (default 'public'): " COMM; COMM=${COMM:-public}
        OUT="$EVIDENCE_DIR/snmpwalk_${SAFE_TARGET}.txt"
        CMD="sudo snmpwalk -v2c -c $COMM $TARGET_RAW | tee $OUT || true"
        run_cmd_and_log "snmpwalk" "$CMD" "$OUT"
        ;;
      3)
        ensure_tool nc "sudo apt-get update && sudo apt-get install -y netcat || true"
        OUT="$EVIDENCE_DIR/smtp_banner_${SAFE_TARGET}.txt"
        CMD="(echo QUIT) | sudo nc -w 3 $TARGET_RAW 25 2>/dev/null | tee $OUT || true"
        run_cmd_and_log "nc" "$CMD" "$OUT"
        echo "If VRFY allowed, example: echo -e \"VRFY postmaster\" | nc $TARGET_RAW 25"
        ;;
      9) return ;;
      0) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid"; pause ;;
    esac
    pause
  done
}

# Main menu loop
while true; do
  clear
  cat <<EOF
Reconnaissance Menu
Target: $TARGET_RAW
Evidence Path: $EVIDENCE_DIR

Choose activity:
  1) Passive Recon
  2) DNS Enumeration
  3) Network Discovery (Hosts/Ports)
  4) Service Fingerprinting
  5) Vulnerability Enumeration
  6) Credential & Auth checks (non-destructive)
  9) Back (change target)
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
    9) exec "$0" ;; # restart entire script (back to beginning)
    0) echo "Exiting..."; exit 0 ;;
    *) echo "Invalid option"; pause ;;
  esac
done
