#!/usr/bin/env bash
# net_threat_vuln_analysis.sh
# OpenBash Pentesting Tools - Threat modeling & Vulnerability analysis
# Version: 1.0
# Purpose: Menu-driven, robust, evidence-aware toolset for threat modeling & vuln analysis (network focus).
# WARNING: Run only against assets you are authorized to test.

set -euo pipefail
IFS=$'\n\t'

##### CONFIG #####
LOGDIR="logs"
mkdir -p "$LOGDIR"
LOGFILE="$LOGDIR/net_threat_vuln_$(date +%Y%m%d-%H%M%S).log"

##### HELPERS #####
timestamp(){ date '+%Y-%m-%d %H:%M:%S'; }
pause(){ read -n1 -rsp $'Press any key to continue...\n'; }

# robust yes/no prompt returning 'y' or 'n'
ask_yesno(){
  local prompt="$1" ans
  while true; do
    read -rp "$prompt (y/n): " ans
    ans="${ans,,}"
    if [[ "$ans" == "y" || "$ans" == "n" ]]; then
      printf '%s' "$ans"
      return 0
    fi
    echo "Please answer 'y' or 'n'."
  done
}

sanitize(){ printf '%s' "$1" | tr '/:' '_' ; }

log(){ echo "[$(timestamp)] $*" | tee -a "$LOGFILE"; }

# generic tool check + optional installer (Enter = default install command; or type custom)
ensure_tool(){
  local bin="$1"; shift
  local default_install_cmd="$*"
  if command -v "$bin" &>/dev/null; then
    return 0
  fi
  echo "[-] Tool '$bin' not found."
  printf "Press Enter to install with default command [%s], or type custom install command: " "$default_install_cmd"
  read -r usercmd
  if [[ -z "$usercmd" ]]; then
    log "[*] Running default install: $default_install_cmd"
    eval "$default_install_cmd"
  else
    log "[*] Running custom install: $usercmd"
    eval "$usercmd"
  fi
  if ! command -v "$bin" &>/dev/null; then
    log "[-] Tool '$bin' still not available after install attempt."
    return 1
  fi
  return 0
}

# run & log (safe eval). cmd is a full string; out is path or pattern for evidence
run_and_log(){
  local tool="$1"; shift
  local cmd="$1"; shift
  local out="$1"; shift || true
  log "EXEC | Tool: $tool | Cmd: $cmd | Out: $out"
  eval "$cmd"
}

##### START LOG HEADER #####
echo "=== OpenBash Pentesting Tools - Threat modeling & Vulnerability analysis ===" | tee -a "$LOGFILE"
log "Start: $(timestamp)"
log "Log file: $LOGFILE"

##### DISCLAIMER & quick RoE check #####
clear
cat <<'EOF'
==================================================================
  OpenBash Pentesting Tools - Threat modeling & Vulnerability analysis
==================================================================
[!] DISCLAIMER: Do not run against systems without explicit, written authorization.
This script expects you to have RoE and scope already. It will prompt for quick confirmations.
==================================================================
EOF
pause

# Quick required confirmations (strict)
for item in "Signed RoE/authorization" "Approved target list (IP/CIDR/domain)" "Approved test windows" ; do
  resp=$(ask_yesno "Confirm you have: $item")
  if [[ "$resp" == "n" ]]; then
    log "Pre-check failed: missing $item. Aborting."
    echo "Missing required item: $item. Exiting."
    exit 1
  fi
  log "Pre-check OK: $item"
done

##### TARGET & EVIDENCE #####
read -rp "Enter target (single IP, CIDR, range, or domain): " TARGET_RAW
SAFE_TARGET=$(sanitize "$TARGET_RAW")
EVIDENCE_DIR="Evidence/${SAFE_TARGET}/$(date +%Y-%m-%d)/threat_analysis"
mkdir -p "$EVIDENCE_DIR"
ln -sfn "$(basename "$(dirname "$EVIDENCE_DIR")")/$(basename "$EVIDENCE_DIR")" "$(dirname "$EVIDENCE_DIR")/latest" 2>/dev/null || true
log "Target: $TARGET_RAW"
log "Evidence dir: $EVIDENCE_DIR"
pause

##### MENU FUNCTIONS #####

# 1) Nmap fingerprinting & NSE usage
do_nmap(){
  echo; echo "=== Nmap: OS/service fingerprinting and NSE (non-destructive defaults) ==="
  ensure_tool nmap "sudo apt update && sudo apt install -y nmap || true" || { echo "nmap required"; pause; return; }
  read -rp "Ports to scan (default top 1000) [enter for default]: " PTS
  PTS=${PTS:-"1-1024"}
  read -rp "Timing (T1..T5, default T3): " TMG; TMG=${TMG:-T3}
  OUT="$EVIDENCE_DIR/nmap_${SAFE_TARGET}_$(date +%H%M%S)"
  CMD="sudo nmap -sS -sV -O -p $PTS -T${TMG:1} --script 'default,safe' \"$TARGET_RAW\" -oA \"$OUT\""
  run_and_log "nmap" "$CMD" "$OUT.*"
  echo "Nmap complete. Outputs: $OUT.*"
  pause
}

# 2) GVM/OpenVAS (GVM CE) - attempt to run via gvm-cli if available
do_gvm(){
  echo; echo "=== GVM/OpenVAS (GVM CE) ==="
  if command -v gvm-cli &>/dev/null; then
    echo "gvm-cli detected. You must have a configured GVM/GMP server and credentials."
    read -rp "Enter GVM target name or host (as configured in GVM): " GVM_TARGET
    read -rp "Enter GVM username: " GVM_USER
    # Do not request password on screen; user can setup env or use gvm-cli ssh auth
    log "Attempting GVM scan for target: $GVM_TARGET (user: $GVM_USER)"
    echo "NOTE: This will call gvm-cli; ensure credentials/config are correct."
    OUT="$EVIDENCE_DIR/gvm_scan_${SAFE_TARGET}_$(date +%H%M%S).xml"
    CMD="gvm-cli socket --gmp-username='$GVM_USER' --gmp-password='<PASSWORD>' --xml '<create_task...>'" # placeholder
    echo "We do not run an automated task creation (requires environment). See log for guidance."
    log "GVM: user MUST run gvm tasks manually or adapt this script. Output placeholder: $OUT"
    echo "GVM integration requires environment-specific setup. Please run credentialed scans via GVM UI or gvm-cli configured session."
  else
    echo "gvm-cli not found. To use GVM, install/configure GVM and use its UI or gvm-cli."
    ensure_tool gvm-cli "sudo apt update && sudo apt install -y gvm || true" || true
  fi
  pause
}

# 3) Nikto (webserver checks)
do_nikto(){
  echo; echo "=== Nikto (webserver checks, non-destructive) ==="
  ensure_tool nikto "sudo apt update && sudo apt install -y nikto || true" || { echo "nikto required"; pause; return; }
  read -rp "Target URL (default https://<target>): " TURL
  TURL=${TURL:-"https://$TARGET_RAW"}
  OUT="$EVIDENCE_DIR/nikto_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="sudo nikto -h \"$TURL\" -output \"$OUT\""
  run_and_log "nikto" "$CMD" "$OUT"
  echo "Nikto results saved to $OUT"
  pause
}

# 4) WhatWeb / Wappalyzer (stack identification)
do_whatweb(){
  echo; echo "=== WhatWeb / Wappalyzer ==="
  if command -v whatweb &>/dev/null; then
    OUT="$EVIDENCE_DIR/whatweb_${SAFE_TARGET}_$(date +%H%M%S).txt"
    CMD="sudo whatweb -v \"$TARGET_RAW\" | tee \"$OUT\""
    run_and_log "whatweb" "$CMD" "$OUT"
    echo "WhatWeb output: $OUT"
  else
    echo "whatweb not found, trying wappalyzer CLI"
    ensure_tool whatweb "sudo apt update && sudo apt install -y whatweb || true" || true
    if command -v whatweb &>/dev/null; then
      do_whatweb
    else
      echo "Neither whatweb nor wappalyzer CLI available. You can install via apt/npm respectively."
    fi
  fi
  pause
}

# 5) Lynis (host hardening) - only for hosts you can run locally or via SSH with credentials
do_lynis(){
  echo; echo "=== Lynis (host hardening checks) ==="
  ensure_tool lynis "sudo apt update && sudo apt install -y lynis || true" || { echo "lynis required"; pause; return; }
  read -rp "Run lynis locally (l) or scan remote SSH host (r)? [l/r]: " MODE; MODE=${MODE,,}
  if [[ "$MODE" == "r" ]]; then
    read -rp "Enter SSH target (user@host): " SSH_TARGET
    OUT="$EVIDENCE_DIR/lynis_ssh_${SAFE_TARGET}_$(date +%H%M%S).txt"
    echo "Will run remote commands via SSH (requires valid credentials)."
    CMD="ssh \"$SSH_TARGET\" 'sudo lynis audit system' | tee \"$OUT\""
    run_and_log "lynis-ssh" "$CMD" "$OUT"
  else
    OUT="$EVIDENCE_DIR/lynis_local_${SAFE_TARGET}_$(date +%H%M%S).txt"
    CMD="sudo lynis audit system | tee \"$OUT\""
    run_and_log "lynis-local" "$CMD" "$OUT"
  fi
  pause
}

# 6) Searchsploit & local exploit lookup
do_searchsploit(){
  echo; echo "=== searchsploit / exploit lookup ==="
  ensure_tool searchsploit "sudo apt update && sudo apt install -y exploitdb || true" || { echo "searchsploit required"; pause; return; }
  read -rp "Provide a product/version string to search (or press Enter to use last nmap results file): " SQUERY
  if [[ -z "$SQUERY" ]]; then
    echo "Searching by nmap output requires you to have an nmap output file. Skipping if not present."
    pause
    return
  fi
  OUT="$EVIDENCE_DIR/searchsploit_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="searchsploit \"$SQUERY\" | tee \"$OUT\""
  run_and_log "searchsploit" "$CMD" "$OUT"
  pause
}

# 7) Vulners via nmap NSE and nuclei templates
do_vulners_nuclei(){
  echo; echo "=== Vulners via nmap NSE / Nuclei templates ==="
  # nmap vulners NSE
  ensure_tool nmap "sudo apt update && sudo apt install -y nmap || true" || true
  ensure_tool nuclei "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest || true" || true

  read -rp "Run nmap vuln NSE? (y/n): " RUNNMAP; RUNNMAP=${RUNNMAP,,}
  if [[ "$RUNNMAP" == "y" ]]; then
    OUT_PREFIX="$EVIDENCE_DIR/nmap_vuln_${SAFE_TARGET}_$(date +%H%M%S)"
    CMD="sudo nmap --script vuln -sV -p 1-65535 \"$TARGET_RAW\" -oA \"$OUT_PREFIX\""
    run_and_log "nmap-vuln" "$CMD" "$OUT_PREFIX.*"
  fi

  read -rp "Run nuclei templates? (y/n): " RUNNUC; RUNNUC=${RUNNUC,,}
  if [[ "$RUNNUC" == "y" ]]; then
    read -rp "Path to nuclei-templates (leave empty to use built-in): " NPATH
    OUT="$EVIDENCE_DIR/nuclei_${SAFE_TARGET}_$(date +%H%M%S).txt"
    if [[ -n "$NPATH" && -f "$NPATH" ]]; then
      CMD="sudo nuclei -l \"$NPATH\" -rate 25 -o \"$OUT\""
    else
      # run nuclei against the single target (primitive)
      CMD="echo \"$TARGET_RAW\" | sudo nuclei -silent -rate 25 -o \"$OUT\""
    fi
    run_and_log "nuclei" "$CMD" "$OUT"
  fi
  pause
}

# Summary / Evidence hashing
do_hash_evidence(){
  echo; echo "=== Generating SHA256 for evidence files ==="
  if [[ ! -d "$EVIDENCE_DIR" ]]; then echo "No evidence directory present."; pause; return; fi
  (cd "$EVIDENCE_DIR" && sha256sum * > sha256sums.txt) && log "SHA256s computed: $EVIDENCE_DIR/sha256sums.txt"
  echo "SHA256 sums saved to $EVIDENCE_DIR/sha256sums.txt"
  pause
}

# Quick menu runner
while true; do
  clear
  cat <<EOF
Threat modeling & Vulnerability analysis - Network focus
Target: $TARGET_RAW
Evidence: $EVIDENCE_DIR

Choose an action:
  1) Nmap: OS/service fingerprinting + default NSE
  2) GVM/OpenVAS (GVM CE) - guide / gvm-cli
  3) Nikto (webserver checks)
  4) WhatWeb / Wappalyzer (stack fingerprint)
  5) Lynis (host hardening)
  6) Searchsploit (local exploit lookup)
  7) Vulners (nmap NSE + nuclei)
  8) Generate SHA256 for evidence files
  9) Exit
EOF
  read -rp "Select [1-9]: " choice
  case "$choice" in
    1) do_nmap ;;
    2) do_gvm ;;
    3) do_nikto ;;
    4) do_whatweb ;;
    5) do_lynis ;;
    6) do_searchsploit ;;
    7) do_vulners_nuclei ;;
    8) do_hash_evidence ;;
    9) echo "Exiting..."; log "Finished: $(timestamp)"; exit 0 ;;
    *) echo "Invalid option"; pause ;;
  esac
done
