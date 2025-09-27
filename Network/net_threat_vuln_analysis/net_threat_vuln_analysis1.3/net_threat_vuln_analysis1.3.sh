#!/usr/bin/env bash
# net_threat_vuln_analysis.sh
# Threat modeling & Vulnerability analysis - Network focus
# Version: 1.3 (patched with robust nuclei runner)
# Author: OpenBash
# WARNING: Run only on authorized targets.

set -euo pipefail
IFS=$'\n\t'

##### CONFIG #####
LOGDIR="$(pwd)/logs"
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

##### nuclei installer (robust) #####
install_nuclei(){
  if command -v nuclei &>/dev/null; then return 0; fi
  log "[*] nuclei not found; attempting robust installer."

  # 1st try apt
  if sudo apt-get update && sudo apt-get install -y nuclei; then
    log "[✓] nuclei installed via apt"
    return 0
  else
    log "[*] apt install nuclei failed or not available"
  fi

  # 2nd try GitHub
  TMPDIR=$(mktemp -d)
  pushd "$TMPDIR" >/dev/null
  log "[*] Querying GitHub Releases API for latest nuclei release..."
  URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
    | grep browser_download_url | grep linux_amd64.zip | cut -d '"' -f 4 | head -n1)

  if [[ -z "$URL" ]]; then
    log "[-] Could not find nuclei release asset."
    popd >/dev/null
    return 1
  fi

  log "[*] Found nuclei asset: $URL"
  wget -q "$URL" -O nuclei_asset.zip
  unzip -q nuclei_asset.zip || { log "[-] unzip failed"; popd >/dev/null; return 1; }
  sudo mv nuclei /usr/local/bin/ || { log "[-] mv failed"; popd >/dev/null; return 1; }
  popd >/dev/null
  rm -rf "$TMPDIR"

  if command -v nuclei &>/dev/null; then
    log "[✓] nuclei installed to /usr/local/bin/nuclei"
    return 0
  else
    log "[-] Failed to install nuclei"
    return 1
  fi
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
  ensure_tool nmap "sudo apt-get update && sudo apt-get install -y nmap || true" || return
  OUT="$EVIDENCE/nmap_${SAFE_TARGET}_$(date +%H%M%S)"
  CMD="sudo nmap -sS -sV -O -T3 --script 'default,safe' \"$TARGET\" -oA \"$OUT\""
  run_and_log nmap "$CMD" "$OUT.*"
  pause
}

do_nikto(){
  ensure_tool nikto "sudo apt-get update && sudo apt-get install -y nikto || true" || return
  OUT="$EVIDENCE/nikto_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="sudo nikto -h \"$TARGET\" -output \"$OUT\""
  run_and_log nikto "$CMD" "$OUT"
  pause
}

do_whatweb(){
  ensure_tool whatweb "sudo apt-get update && sudo apt-get install -y whatweb || true" || return
  OUT="$EVIDENCE/whatweb_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="sudo whatweb \"$TARGET\" | tee \"$OUT\""
  run_and_log whatweb "$CMD" "$OUT"
  pause
}

do_lynis(){
  ensure_tool lynis "sudo apt-get update && sudo apt-get install -y lynis || true" || return
  OUT="$EVIDENCE/lynis_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="sudo lynis audit system | tee \"$OUT\""
  run_and_log lynis "$CMD" "$OUT"
  pause
}

do_searchsploit(){
  ensure_tool searchsploit "sudo apt-get update && sudo apt-get install -y exploitdb || true" || return
  read -rp "Enter search term: " TERM
  OUT="$EVIDENCE/searchsploit_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="searchsploit \"$TERM\" | tee \"$OUT\""
  run_and_log searchsploit "$CMD" "$OUT"
  pause
}

do_vulners(){
  ensure_tool nmap "sudo apt-get update && sudo apt-get install -y nmap || true" || true

  # nuclei install if missing
  if command -v nuclei &>/dev/null; then
    log "[*] nuclei detected at: $(command -v nuclei)"
    log "[*] nuclei version: $(nuclei -version 2>&1 | tr '\n' ' ' || true)"
  else
    log "[*] nuclei not found; attempting robust installer."
    install_nuclei || log "[-] nuclei installer returned non-zero; proceeding without nuclei unless available."
  fi

  read -rp "Run nmap vuln NSE? (y/n): " r; r=${r,,}
  if [[ "$r" == "y" ]]; then
    OUT="$EVIDENCE/nmap_vuln_${SAFE_TARGET}_$(date +%H%M%S)"
    CMD="sudo nmap --script vuln -sV \"$TARGET\" -oA \"$OUT\""
    run_and_log nmap-vuln "$CMD" "$OUT.*"
  fi

  if command -v nuclei &>/dev/null; then
    OUT="$EVIDENCE/nuclei_${SAFE_TARGET}_$(date +%H%M%S).txt"

    # Try with -rate
    CMD_TRY="echo \"$TARGET\" | sudo nuclei -silent -rate 25 -o \"$OUT\" 2> \"$EVIDENCE/nuclei_stderr.txt\""
    log "[*] Attempting nuclei with -rate..."
    set +e
    eval "$CMD_TRY"
    RC=$?
    set -e

    if [[ $RC -eq 0 ]]; then
      log "[✓] nuclei ran with -rate; output: $OUT"
    else
      STDERR_CONTENT=$(cat \"$EVIDENCE/nuclei_stderr.txt\" 2>/dev/null || true)
      log "[!] nuclei with -rate failed (rc=$RC). stderr: ${STDERR_CONTENT:0:200}"
      CMD_FALL="echo \"$TARGET\" | sudo nuclei -silent -o \"$OUT\" 2> \"$EVIDENCE/nuclei_stderr2.txt\""
      log "[*] Retrying nuclei without -rate..."
      set +e
      eval "$CMD_FALL"
      RC2=$?
      set -e
      if [[ $RC2 -eq 0 ]]; then
        log "[✓] nuclei ran without -rate; output: $OUT"
      else
        STDERR2=$(cat \"$EVIDENCE/nuclei_stderr2.txt\" 2>/dev/null || true)
        log "[-] nuclei failed both attempts. stderr: ${STDERR2:0:200}"
        echo "nuclei execution failed. Check logs and $EVIDENCE/nuclei_stderr*.txt"
      fi
    fi
  else
    log "[!] nuclei not installed; skipped nuclei run."
    echo "nuclei not available - skipped."
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
