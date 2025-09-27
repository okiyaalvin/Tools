#!/usr/bin/env bash
# net_recon_helper.sh - Network Recon Helper (OpenBash Pentesting Tools)
# Author: PentestGPT (OpenBash)
# Usage: ./net_recon_helper.sh
# Requires: bash, common pentest tools (amass, subfinder, masscan, nmap, etc.) - checks availability before running.

set -euo pipefail
IFS=$'\n\t'

# Helpers
pause() { read -rp $'Press Enter to continue...' _; }
confirm_yesno() {
  local prompt="$1"
  local ans
  while true; do
    read -rp "$prompt [y/n]: " ans
    ans="${ans,,}"  # lowercase
    case "$ans" in
      y) return 0 ;;
      n) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}
check_cmd() {
  command -v "$1" >/dev/null 2>&1 || return 1
}
install_hint() {
  echo "Tool '$1' is not found in PATH. Install it or add to PATH before using this option."
}

# Validate simple CIDR or IP (very basic)
validate_ip_or_cidr() {
  local in="$1"
  if [[ "$in" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]{1,2})?$ ]]; then
    return 0
  fi
  if [[ "$in" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then return 0; fi
  return 1
}

# Global variables
TARGET_INPUT=""
TARGET_TYPE="" # ip, cidr, domain
EVIDENCE_DIR="recon_evidence_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVIDENCE_DIR"

# Main menus and flows
main_menu() {
  while true; do
    clear
    cat <<'EOF'
OpenBash Pentesting Tools - Network Recon Helper
------------------------------------------------
1) Enter target (public IP / IP range / subnet / domain)
2) RoE & Checklist (required)
3) Recon activities
4) Evidence & packaging
5) Exit
EOF
    read -rp "Choose an option [1-5]: " opt
    case "$opt" in
      1) input_target ;;
      2) roe_checklist ;;
      3) activities_menu ;;
      4) evidence_menu ;;
      5) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid option"; pause ;;
    esac
  done
}

input_target() {
  while true; do
    clear
    cat <<'EOF'
Select target input type:
1) Single public IP (e.g., 198.51.100.12)
2) CIDR / subnet (e.g., 198.51.100.0/24)
3) Domain name (e.g., example.com)
4) Back to main menu
EOF
    read -rp "Select [1-4]: " choice
    case "$choice" in
      1)
        read -rp "Enter single public IP: " t
        if validate_ip_or_cidr "$t"; then TARGET_INPUT="$t"; TARGET_TYPE="ip"; echo "Set target: $TARGET_INPUT"; pause; return; else echo "Invalid IP format."; pause; fi
        ;;
      2)
        read -rp "Enter CIDR (e.g., 198.51.100.0/24): " t
        if validate_ip_or_cidr "$t"; then TARGET_INPUT="$t"; TARGET_TYPE="cidr"; echo "Set target: $TARGET_INPUT"; pause; return; else echo "Invalid CIDR format."; pause; fi
        ;;
      3)
        read -rp "Enter domain (e.g., example.com): " t
        if [[ -n "$t" ]]; then TARGET_INPUT="$t"; TARGET_TYPE="domain"; echo "Set target: $TARGET_INPUT"; pause; return; else echo "Invalid domain."; pause; fi
        ;;
      4) return ;;
      *) echo "Invalid"; pause ;;
    esac
  done
}

roe_checklist() {
  clear
  echo "Pre-engagement checklist (RoE & required documents)"
  echo "For each item type y (yes) if present or n (no) if missing. Non-case-sensitive."
  echo

  declare -a docs=("Signed RoE/Authorization" "Approved target list (IP/CIDR/domains)" "Approved test windows" "Credentials approval (if credentialed scans planned)" "Backup/snapshot confirmation for critical systems" "Emergency contact list (phone/email)")
  local all_ok=0
  for d in "${docs[@]}"; do
    if confirm_yesno "Do you have: $d?"; then
      echo "OK: $d" >> "$EVIDENCE_DIR/roe_checklist.log"
    else
      echo "MISSING: $d"
      echo "Missing required item: $d" >> "$EVIDENCE_DIR/roe_checklist.log"
      echo
      echo "You are not fully authorized to proceed. Close the program and obtain required documents."
      pause
      return 1
    fi
  done
  echo "All required documents present." | tee -a "$EVIDENCE_DIR/roe_checklist.log"
  pause
  return 0
}

activities_menu() {
  # ensure target and roe are set
  if [[ -z "$TARGET_INPUT" ]]; then
    echo "No target set. Please set a target first (option 1)." ; pause ; return
  fi
  if [[ ! -f "$EVIDENCE_DIR/roe_checklist.log" ]]; then
    echo "RoE checklist not confirmed. Please run 'RoE & Checklist' (option 2) first." ; pause ; return
  fi

  while true; do
    clear
    cat <<EOF
Recon Activities (network-focused) - Target: $TARGET_INPUT ($TARGET_TYPE)
--------------------------------------------------------
1) Passive recon / OSINT
2) DNS & name resolution enumeration
3) High-speed network discovery (masscan / naabu / fping)
4) Service discovery & fingerprinting (nmap, httpx, sslscan)
5) Lightweight vulnerability enumeration (nuclei, nikto)
6) Credential & auth discovery (non-destructive checks)
7) Back to main menu
EOF
    read -rp "Select activity [1-7]: " act
    case "$act" in
      1) passive_menu ;;
      2) dns_menu ;;
      3) fastscan_menu ;;
      4) service_menu ;;
      5) vuln_menu ;;
      6) auth_menu ;;
      7) return ;;
      *) echo "Invalid"; pause ;;
    esac
  done
}

# Passive recon menu
passive_menu() {
  while true; do
    clear
    cat <<EOF
Passive Recon / OSINT
Target: $TARGET_INPUT
Options:
1) amass (passive enum)
2) subfinder (passive)
3) theHarvester
4) crt.sh (cert transparency via curl)
5) spiderfoot (launch web UI if installed)
6) Back
7) Exit
EOF
    read -rp "Select [1-7]: " p
    case "$p" in
      1) run_amass ;;
      2) run_subfinder ;;
      3) run_theharvester ;;
      4) run_crtsh ;;
      5) run_spiderfoot ;;
      6) return ;;
      7) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid"; pause ;;
    esac
  done
}

run_amass() {
  if ! check_cmd amass; then install_hint amass; pause; return; fi
  out="$EVIDENCE_DIR/amass_passive_$(date -u +%Y%m%dT%H%M%SZ).txt"
  echo "Running amass (passive) against: $TARGET_INPUT"
  read -rp "Extra amass args (or press Enter): " extra
  amass enum -passive -d "$TARGET_INPUT" $extra -o "$out"
  echo "Saved: $out"
  pause
}

run_subfinder() {
  if ! check_cmd subfinder; then install_hint subfinder; pause; return; fi
  out="$EVIDENCE_DIR/subfinder_$(date -u +%Y%m%dT%H%M%SZ).txt"
  echo "Running subfinder against: $TARGET_INPUT"
  read -rp "Extra subfinder args (or press Enter): " extra
  subfinder -d "$TARGET_INPUT" $extra -o "$out"
  echo "Saved: $out"
  pause
}

run_theharvester() {
  if ! check_cmd theHarvester; then install_hint theHarvester; pause; return; fi
  out="$EVIDENCE_DIR/theharvester_$(date -u +%Y%m%dT%H%M%SZ).html"
  echo "Running theHarvester against: $TARGET_INPUT (source: all)"
  theHarvester -d "$TARGET_INPUT" -b all -l 500 -f "$out"
  echo "Saved: $out"
  pause
}

run_crtsh() {
  out="$EVIDENCE_DIR/crtsh_$(date -u +%Y%m%dT%H%M%SZ).txt"
  echo "Querying crt.sh for certificate transparency (may return duplicates)."
  curl -s "https://crt.sh/?q=%25.$TARGET_INPUT&output=json" | jq -r '.[].name_value' 2>/dev/null | tr ',' '\n' | sed 's/\*\.//g' | sort -u > "$out"
  echo "Saved: $out"
  pause
}

run_spiderfoot() {
  if ! check_cmd spiderfoot; then install_hint spiderfoot; pause; return; fi
  echo "Starting spiderfoot web UI (default: http://127.0.0.1:5001). Press Ctrl+C to stop."
  spiderfoot -l 127.0.0.1:5001
  pause
}

# DNS menu
dns_menu() {
  while true; do
    clear
    cat <<EOF
DNS & Name Resolution Enumeration
Target: $TARGET_INPUT
1) dnsrecon (records + AXFR)
2) massdns (validate large subdomain lists)
3) dig manual check
4) sublist3r (wordlist bruteforce)
5) Back
6) Exit
EOF
    read -rp "Select [1-6]: " d
    case "$d" in
      1) run_dnsrecon ;;
      2) run_massdns ;;
      3) run_dig ;;
      4) run_sublist3r ;;
      5) return ;;
      6) exit 0 ;;
      *) echo "Invalid"; pause ;;
    esac
  done
}

run_dnsrecon() {
  if ! check_cmd dnsrecon; then install_hint dnsrecon; pause; return; fi
  out="$EVIDENCE_DIR/dnsrecon_$(date -u +%Y%m%dT%H%M%SZ).txt"
  dnsrecon -d "$TARGET_INPUT" -t std -a -o "$out"
  echo "Saved: $out"
  pause
}

run_massdns() {
  if ! check_cmd massdns; then install_hint massdns; pause; return; fi
  read -rp "Path to subdomain wordlist to validate: " wl
  if [[ ! -f "$wl" ]]; then echo "Wordlist not found"; pause; return; fi
  out="$EVIDENCE_DIR/massdns_$(date -u +%Y%m%dT%H%M%SZ).txt"
  read -rp "Resolvers file path (default: /etc/resolv.conf or resolvers.txt): " resolvers
  resolvers=${resolvers:-/etc/resolv.conf}
  massdns -r "$resolvers" -t A -o S -w "$out" "$wl"
  echo "Saved: $out"
  pause
}

run_dig() {
  read -rp "Enter dig query (default: ANY $TARGET_INPUT): " q
  q=${q:-"ANY $TARGET_INPUT"}
  echo "Running: dig $q"
  dig $q +noall +answer
  pause
}

run_sublist3r() {
  if ! check_cmd sublist3r; then install_hint sublist3r; pause; return; fi
  out="$EVIDENCE_DIR/sublist3r_$(date -u +%Y%m%dT%H%M%SZ).txt"
  sublist3r -d "$TARGET_INPUT" -o "$out"
  echo "Saved: $out"
  pause
}

# Fast scan menu
fastscan_menu() {
  while true; do
    clear
    cat <<EOF
High-speed Network Discovery
Target: $TARGET_INPUT
1) masscan (fast port sweep)
2) naabu (fast port discovery)
3) fping (ICMP sweep)
4) RustScan (quick nmap frontend)
5) Back
6) Exit
EOF
    read -rp "Select [1-6]: " f
    case "$f" in
      1) run_masscan ;;
      2) run_naabu ;;
      3) run_fping ;;
      4) run_rustscan ;;
      5) return ;;
      6) exit 0 ;;
      *) echo "Invalid"; pause ;;
    esac
  done
}

run_masscan() {
  if ! check_cmd masscan; then install_hint masscan; pause; return; fi
  read -rp "Ports to scan (default: 1-65535): " ports
  ports=${ports:-1-65535}
  read -rp "Rate (packets per second, recommended conservative 100-1000): " rate
  rate=${rate:-100}
  out="$EVIDENCE_DIR/masscan_$(date -u +%Y%m%dT%H%M%SZ).txt"
  echo "Running masscan on $TARGET_INPUT ports $ports rate $rate (this may take time)..."
  masscan "$TARGET_INPUT" -p"$ports" --rate "$rate" -oL "$out"
  echo "Saved: $out"
  pause
}

run_naabu() {
  if ! check_cmd naabu; then install_hint naabu; pause; return; fi
  read -rp "Target list file (leave empty to use single target): " tfile
  if [[ -n "$tfile" && ! -f "$tfile" ]]; then echo "File not found"; pause; return; fi
  out="$EVIDENCE_DIR/naabu_$(date -u +%Y%m%dT%H%M%SZ).txt"
  if [[ -n "$tfile" ]]; then
    naabu -list "$tfile" -o "$out"
  else
    naabu -host "$TARGET_INPUT" -o "$out"
  fi
  echo "Saved: $out"
  pause
}

run_fping() {
  if ! check_cmd fping; then install_hint fping; pause; return; fi
  out="$EVIDENCE_DIR/fping_$(date -u +%Y%m%dT%H%M%SZ).txt"
  echo "Running fping sweep on $TARGET_INPUT (this may require CIDR input)"
  fping -a -g "$TARGET_INPUT" 2>/dev/null > "$out" || true
  echo "Saved: $out"
  pause
}

run_rustscan() {
  if ! check_cmd rustscan; then install_hint rustscan; pause; return; fi
  outprefix="$EVIDENCE_DIR/rustscan_$(date -u +%Y%m%dT%H%M%SZ)"
  rustscan -a "$TARGET_INPUT" --ulimit 5000 -b 500 -- -sV -A -oA "$outprefix"
  echo "RustScan + Nmap outputs saved with prefix: $outprefix.*"
  pause
}

# Service discovery & fingerprinting
service_menu() {
  while true; do
    clear
    cat <<EOF
Service Discovery & Fingerprinting
Target: $TARGET_INPUT
1) nmap (sV, NSE safe)
2) httpx (HTTP probing)
3) sslscan / testssl.sh
4) banner grabbing (nc / curl)
5) Back
6) Exit
EOF
    read -rp "Select [1-6]: " s
    case "$s" in
      1) run_nmap ;;
      2) run_httpx ;;
      3) run_sslchecks ;;
      4) run_banner ;;
      5) return ;;
      6) exit 0 ;;
      *) echo "Invalid"; pause ;;
    esac
  done
}

run_nmap() {
  if ! check_cmd nmap; then install_hint nmap; pause; return; fi
  read -rp "Ports (default: top 1000): " ports
  ports=${ports:-"1-65535"}
  read -rp "Timing template (T3 default) [T1..T5]: " timing
  timing=${timing:-T3}
  outprefix="$EVIDENCE_DIR/nmap_$(date -u +%Y%m%dT%H%M%SZ)"
  echo "Running nmap -sS -sV -p $ports -T${timing:1} on $TARGET_INPUT"
  nmap -sS -sV -p "$ports" -T"${timing:1}" --script "default,safe" "$TARGET_INPUT" -oA "$outprefix"
  echo "Saved: $outprefix.*"
  pause
}

run_httpx() {
  if ! check_cmd httpx; then install_hint httpx; pause; return; fi
  read -rp "Input file with hosts/subdomains (leave empty to use single target): " tfile
  out="$EVIDENCE_DIR/httpx_$(date -u +%Y%m%dT%H%M%SZ).txt"
  if [[ -n "$tfile" && -f "$tfile" ]]; then
    httpx -l "$tfile" -o "$out"
  else
    httpx -silent -status-code -title -u "http://$TARGET_INPUT" -o "$out" 2>/dev/null || httpx -silent -status-code -title -u "https://$TARGET_INPUT" -o "$out"
  fi
  echo "Saved: $out"
  pause
}

run_sslchecks() {
  if check_cmd sslscan; then
    echo "Running sslscan..."
    sslscan "$TARGET_INPUT" | tee "$EVIDENCE_DIR/sslscan_$(date -u +%Y%m%dT%H%M%SZ).txt"
  elif [[ -f "./testssl.sh" ]]; then
    echo "Running testssl.sh..."
    ./testssl.sh --fast "$TARGET_INPUT" | tee "$EVIDENCE_DIR/testssl_$(date -u +%Y%m%dT%H%M%SZ).txt"
  else
    install_hint sslscan or "./testssl.sh"
  fi
  pause
}

run_banner() {
  read -rp "Service and port to banner-grab (e.g., smtp:25 or 22): " sp
  if [[ -z "$sp" ]]; then echo "No service/port provided"; pause; return; fi
  host="$TARGET_INPUT"
  if [[ "$sp" == *":"* ]]; then
    port="${sp#*:}"
  else
    port="$sp"
  fi
  echo "Banner grabbing $host:$port (timeout 3s) ..."
  (echo -e "" | nc -w 3 "$host" "$port") 2>/dev/null | sed -n '1,50p' | tee "$EVIDENCE_DIR/banner_${host}_${port}_$(date -u +%Y%m%dT%H%M%SZ).txt"
  pause
}

# Vulnerability enumeration (non-destructive)
vuln_menu() {
  while true; do
    clear
    cat <<EOF
Lightweight Vulnerability Enumeration (non-destructive)
Target: $TARGET_INPUT
1) nuclei (templates) - throttle carefully
2) nikto (webserver checks)
3) nmap --script vuln (safe first)
4) Back
5) Exit
EOF
    read -rp "Select [1-5]: " v
    case "$v" in
      1) run_nuclei ;;
      2) run_nikto ;;
      3) run_nmap_vuln ;;
      4) return ;;
      5) exit 0 ;;
      *) echo "Invalid"; pause ;;
    esac
  done
}

run_nuclei() {
  if ! check_cmd nuclei; then install_hint nuclei; pause; return; fi
  read -rp "Targets file (or leave empty for single target): " tfile
  read -rp "Rate (templates/sec, conservative default 25): " rate
  rate=${rate:-25}
  out="$EVIDENCE_DIR/nuclei_$(date -u +%Y%m%dT%H%M%SZ).txt"
  if [[ -n "$tfile" && -f "$tfile" ]]; then
    nuclei -l "$tfile" -rate "$rate" -o "$out"
  else
    echo "$TARGET_INPUT" > "$EVIDENCE_DIR/_tmp_target.txt"
    nuclei -l "$EVIDENCE_DIR/_tmp_target.txt" -rate "$rate" -o "$out"
    rm -f "$EVIDENCE_DIR/_tmp_target.txt"
  fi
  echo "Saved: $out"
  pause
}

run_nikto() {
  if ! check_cmd nikto; then install_hint nikto; pause; return; fi
  read -rp "Target URL (default: https://$TARGET_INPUT): " tgt
  tgt=${tgt:-"https://$TARGET_INPUT"}
  out="$EVIDENCE_DIR/nikto_$(date -u +%Y%m%dT%H%M%SZ).txt"
  nikto -h "$tgt" -o "$out"
  echo "Saved: $out"
  pause
}

run_nmap_vuln() {
  if ! check_cmd nmap; then install_hint nmap; pause; return; fi
  outprefix="$EVIDENCE_DIR/nmap_vuln_$(date -u +%Y%m%dT%H%M%SZ)"
  nmap --script vuln -sV -p 1-65535 "$TARGET_INPUT" -oA "$outprefix"
  echo "Saved: $outprefix.*"
  pause
}

# Auth & credential checks (non-destructive)
auth_menu() {
  while true; do
    clear
    cat <<EOF
Credential & Authentication Discovery (only if explicitly allowed)
Target: $TARGET_INPUT
1) SMB anonymous check (smbclient / enum4linux)
2) SNMP (public community) check
3) SMTP VRFY / banner checks
4) Back
5) Exit
EOF
    read -rp "Select [1-5]: " a
    case "$a" in
      1) run_smb_checks ;;
      2) run_snmp_checks ;;
      3) run_smtp_vrfy ;;
      4) return ;;
      5) exit 0 ;;
      *) echo "Invalid"; pause ;;
    esac
  done
}

run_smb_checks() {
  if ! check_cmd smbclient && ! check_cmd enum4linux; then install_hint "smbclient/enum4linux"; pause; return; fi
  echo "Attempting anonymous SMB query..."
  if check_cmd smbclient; then smbclient -L "//$TARGET_INPUT" -N | tee "$EVIDENCE_DIR/smbclient_$(date -u +%Y%m%dT%H%M%SZ).txt"; fi
  if check_cmd enum4linux; then enum4linux -a "$TARGET_INPUT" | tee "$EVIDENCE_DIR/enum4linux_$(date -u +%Y%m%dT%H%M%SZ).txt"; fi
  pause
}

run_snmp_checks() {
  if ! check_cmd snmpwalk && ! check_cmd onesixtyone; then install_hint "snmpwalk/onesixtyone"; pause; return; fi
  echo "Checking SNMP public community 'public' by default (read-only)."
  read -rp "SNMP community (default 'public'): " comm
  comm=${comm:-public}
  if check_cmd snmpwalk; then snmpwalk -v2c -c "$comm" "$TARGET_INPUT" | tee "$EVIDENCE_DIR/snmpwalk_$(date -u +%Y%m%dT%H%M%SZ).txt"; fi
  if check_cmd onesixtyone; then onesixtyone -c "$comm" "$TARGET_INPUT" | tee "$EVIDENCE_DIR/onesixtyone_$(date -u +%Y%m%dT%H%M%SZ).txt"; fi
  pause
}

run_smtp_vrfy() {
  echo "SMTP banner / VRFY (many servers will reject VRFY)."
  if check_cmd nc; then
    { echo "QUIT"; } | nc -w 3 "$TARGET_INPUT" 25 2>/dev/null | tee "$EVIDENCE_DIR/smtp_banner_$(date -u +%Y%m%dT%H%M%SZ).txt"
    echo "If VRFY allowed, run: echo -e \"VRFY postmaster\" | nc $TARGET_INPUT 25"
  else
    install_hint nc
  fi
  pause
}

# Evidence & packaging
evidence_menu() {
  while true; do
    clear
    cat <<EOF
Evidence & Packaging
1) List evidence files
2) Hash evidence (sha256)
3) Package & GPG encrypt evidence bundle
4) Back
5) Exit
EOF
    read -rp "Select [1-5]: " e
    case "$e" in
      1) ls -lah "$EVIDENCE_DIR"; pause ;;
      2) sha_menu ;;
      3) package_evidence ;;
      4) return ;;
      5) exit 0 ;;
      *) echo "Invalid"; pause ;;
    esac
  done
}

sha_menu() {
  echo "Computing sha256 for files in $EVIDENCE_DIR..."
  (cd "$EVIDENCE_DIR" && sha256sum * > sha256sums.txt) || true
  echo "Saved: $EVIDENCE_DIR/sha256sums.txt"
  pause
}

package_evidence() {
  read -rp "Output archive name (default evidence_bundle.tar.gz): " an
  an=${an:-evidence_bundle.tar.gz}
  tar -czf "$an" -C "$EVIDENCE_DIR" .
  echo "Created $an"
  if check_cmd gpg; then
    if confirm_yesno "Encrypt $an with GPG for recipient? (you will be prompted for recipient)"; then
      read -rp "GPG recipient (email or key id): " rec
      gpg --encrypt --recipient "$rec" "$an"
      echo "Encrypted: ${an}.gpg"
    fi
  else
    install_hint gpg
  fi
  pause
}

# Start
trap 'echo "Interrupted. Exiting."; exit 1' INT TERM
echo "Welcome — OpenBash Pentesting Tools (https://www.openbash.com)"
echo "Network Recon Helper starting. Evidence directory: $EVIDENCE_DIR"
echo
main_menu
