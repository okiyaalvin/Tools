#!/usr/bin/env bash
# net_threat_vuln_analysis.sh
# Threat modeling & Vulnerability analysis - Network focus
# Version: 1.1
# Author: OpenBash
# WARNING: Run only on authorized targets.

set -euo pipefail
IFS=$'\n\t'

##### CONFIG #####
LOGDIR="logs"
mkdir -p "$LOGDIR"
LOGFILE="$LOGDIR/net_threat_vuln_$(date +%Y%m%d-%H%M%S).log"

##### HELPERS #####
timestamp(){ date '+%Y-%m-%d %H:%M:%S'; }
pause(){ read -n1 -rsp $'Press any key to continue...\n'; }
sanitize(){ printf '%s' "$1" | tr '/:' '_' ; }
log(){ echo "[$(timestamp)] $*" | tee -a "$LOGFILE"; }

ask_yesno(){
  local ans
  while true; do
    read -rp "$1 (y/n): " ans
    ans="${ans,,}"
    if [[ "$ans" == "y" || "$ans" == "n" ]]; then
      printf '%s' "$ans"
      return
    fi
    echo "Please answer 'y' or 'n'."
  done
}

# custom tool installer
ensure_tool(){
  local bin="$1"; shift
  local default_install="$*"
  if command -v "$bin" &>/dev/null; then return 0; fi
  echo "[-] Tool '$bin' not found."
  printf "Press Enter to install with default [%s], or type custom command: " "$default_install"
  read -r usercmd
  if [[ -z "$usercmd" ]]; then
    log "[*] Installing: $default_install"
    eval "$default_install"
  else
    log "[*] Installing: $usercmd"
    eval "$usercmd"
  fi
  command -v "$bin" &>/dev/null
}

# nuclei installer fix
install_nuclei(){
  if command -v nuclei &>/dev/null; then return 0; fi
  echo "[*] Installing nuclei (binary method)..."
  TMPDIR=$(mktemp -d)
  cd "$TMPDIR"
  wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.8/nuclei_3.3.8_linux_amd64.zip -O nuclei.zip
  unzip nuclei.zip
  sudo mv nuclei /usr/local/bin/
  cd - >/dev/null
  rm -rf "$TMPDIR"
  nuclei -version || { echo "[-] Failed to install nuclei"; return 1; }
  return 0
}

run_and_log(){
  local tool="$1"; local cmd="$2"; local out="${3:-}"
  log "EXEC | Tool: $tool | Cmd: $cmd | Out: $out"
  eval "$cmd"
}

##### DISCLAIMER #####
clear
cat <<'EOF'
==================================================================
 Threat Modeling & Vulnerability Analysis - Network Focus
==================================================================
[!] WARNING: Unauthorized testing is illegal.
Ensure you have signed RoE and authorization before proceeding.
==================================================================
EOF
pause

for item in "Signed RoE/authorization" "Approved target list" "Approved test window"; do
  resp=$(ask_yesno "Confirm $item")
  if [[ "$resp" == "n" ]]; then
    log "Missing: $item. Exiting."
    exit 1
  fi
done

##### TARGET #####
read -rp "Enter target (IP, CIDR, range, or domain): " TARGET
SAFE_TARGET=$(sanitize "$TARGET")
EVIDENCE="Evidence/${SAFE_TARGET}/$(date +%Y-%m-%d)/threat_analysis"
mkdir -p "$EVIDENCE"
log "Target: $TARGET"
log "Evidence dir: $EVIDENCE"

##### MENU FUNCTIONS #####
do_nmap(){
  ensure_tool nmap "sudo apt update && sudo apt install -y nmap || true" || return
  OUT="$EVIDENCE/nmap_${SAFE_TARGET}_$(date +%H%M%S)"
  CMD="sudo nmap -sS -sV -O -T3 --script 'default,safe' \"$TARGET\" -oA \"$OUT\""
  run_and_log nmap "$CMD" "$OUT.*"
  pause
}

do_nikto(){
  ensure_tool nikto "sudo apt update && sudo apt install -y nikto || true" || return
  OUT="$EVIDENCE/nikto_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="sudo nikto -h \"$TARGET\" -output \"$OUT\""
  run_and_log nikto "$CMD" "$OUT"
  pause
}

do_whatweb(){
  ensure_tool whatweb "sudo apt update && sudo apt install -y whatweb || true" || return
  OUT="$EVIDENCE/whatweb_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="sudo whatweb \"$TARGET\" | tee \"$OUT\""
  run_and_log whatweb "$CMD" "$OUT"
  pause
}

do_lynis(){
  ensure_tool lynis "sudo apt update && sudo apt install -y lynis || true" || return
  OUT="$EVIDENCE/lynis_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="sudo lynis audit system | tee \"$OUT\""
  run_and_log lynis "$CMD" "$OUT"
  pause
}

do_searchsploit(){
  ensure_tool searchsploit "sudo apt update && sudo apt install -y exploitdb || true" || return
  read -rp "Enter search term: " TERM
  OUT="$EVIDENCE/searchsploit_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="searchsploit \"$TERM\" | tee \"$OUT\""
  run_and_log searchsploit "$CMD" "$OUT"
  pause
}

do_vulners(){
  ensure_tool nmap "sudo apt update && sudo apt install -y nmap || true" || true
  install_nuclei || true

  read -rp "Run nmap vuln NSE? (y/n): " r; r=${r,,}
  if [[ "$r" == "y" ]]; then
    OUT="$EVIDENCE/nmap_vuln_${SAFE_TARGET}_$(date +%H%M%S)"
    CMD="sudo nmap --script vuln -sV \"$TARGET\" -oA \"$OUT\""
    run_and_log nmap-vuln "$CMD" "$OUT.*"
  fi

  if command -v nuclei &>/dev/null; then
    OUT="$EVIDENCE/nuclei_${SAFE_TARGET}_$(date +%H%M%S).txt"
    CMD="echo \"$TARGET\" | sudo nuclei -silent -rate 25 -o \"$OUT\""
    run_and_log nuclei "$CMD" "$OUT"
  else
    echo "[!] nuclei not available."
  fi
  pause
}

do_hash(){
  (cd "$EVIDENCE" && sha256sum * > sha256sums.txt)
  echo "Hashes saved in $EVIDENCE/sha256sums.txt"
  pause
}

##### MENU LOOP #####
while true; do
  clear
  cat <<EOF
Threat modeling & Vulnerability analysis
Target: $TARGET
Evidence: $EVIDENCE

1) Nmap (fingerprint + NSE)
2) Nikto (web checks)
3) WhatWeb (stack ID)
4) Lynis (hardening)
5) Searchsploit
6) Vulners (nmap NSE + nuclei)
7) Hash evidence
9) Exit
EOF
  read -rp "Select [1-9]: " opt
  case "$opt" in
    1) do_nmap ;;
    2) do_nikto ;;
    3) do_whatweb ;;
    4) do_lynis ;;
    5) do_searchsploit ;;
    6) do_vulners ;;
    7) do_hash ;;
    9) exit 0 ;;
    *) echo "Invalid option"; pause ;;
  esac
done
