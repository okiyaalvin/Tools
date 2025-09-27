#!/usr/bin/env bash
# net_threat_vuln_analysis1.2.sh
# Threat modeling & Vulnerability analysis - Network focus
# Version: 1.2
# Robust nuclei installer via GitHub Releases API (no hardcoded version).
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

# Generic ensure tool with default install command or custom
ensure_tool(){
  local bin="$1"; shift
  local default_install="$*"
  if command -v "$bin" &>/dev/null; then return 0; fi
  echo "[-] Tool '$bin' not found."
  printf "Press Enter to install with default [%s], or type custom command and press Enter: " "$default_install"
  read -r usercmd
  if [[ -z "$usercmd" ]]; then
    log "[*] Installing: $default_install"
    eval "$default_install"
  else
    log "[*] Installing (custom): $usercmd"
    eval "$usercmd"
  fi
  command -v "$bin" &>/dev/null
}

# Robust nuclei installer:
# 1) Try apt (if available)
# 2) Try GitHub Releases API to find latest linux amd64 asset (zip/tar.gz)
# 3) Extract nuclei binary and move to /usr/local/bin
# 4) Allow custom command if provided
install_nuclei(){
  if command -v nuclei &>/dev/null; then
    log "[*] nuclei already installed: $(command -v nuclei)"
    return 0
  fi

  echo "[*] Attempting to install nuclei..."
  # 1) apt (easy path)
  if sudo apt-get update && sudo apt-get install -y nuclei >/dev/null 2>&1; then
    if command -v nuclei &>/dev/null; then
      log "[*] Installed nuclei via apt"
      return 0
    fi
  else
    log "[*] apt install nuclei failed or not available"
  fi

  # 2) ensure curl & unzip present (needed to fetch & extract)
  if ! command -v curl &>/dev/null; then
    echo "[-] 'curl' not found. Will try to install it (requires sudo)."
    read -rp "Install curl now? (y to install automatically, any other to skip): " resp
    if [[ "${resp,,}" == "y" ]]; then
      sudo apt-get update && sudo apt-get install -y curl || true
    else
      echo "Skipping curl installation — you must provide custom install command for nuclei."
    fi
  fi
  if ! command -v unzip &>/dev/null; then
    echo "[-] 'unzip' not found. Will try to install it (requires sudo)."
    read -rp "Install unzip now? (y to install automatically, any other to skip): " resp2
    if [[ "${resp2,,}" == "y" ]]; then
      sudo apt-get update && sudo apt-get install -y unzip || true
    else
      echo "Skipping unzip installation — extraction may fail."
    fi
  fi

  # 3) Use GitHub Releases API to find latest release asset for linux amd64
  if command -v curl &>/dev/null; then
    log "[*] Querying GitHub Releases API for latest nuclei release..."
    API_JSON="$(curl -s -H "Accept: application/vnd.github.v3+json" https://api.github.com/repos/projectdiscovery/nuclei/releases/latest || true)"

    if [[ -z "$API_JSON" ]]; then
      log "[-] Failed to query GitHub Releases API. You may provide a custom install command."
      return 1
    fi

    # try to extract browser_download_url for linux amd64 zip/tar
    DOWNLOAD_URL="$(printf '%s' "$API_JSON" | grep -oP '"browser_download_url":\s*"\K([^"]+)' | grep -E 'linux.*(amd64|x86_64).*\.(zip|tar\.gz|tgz|gz|bz2)' | head -n1 || true)"

    if [[ -z "$DOWNLOAD_URL" ]]; then
      # try another pattern: asset name contains 'linux_amd64' or 'linux-x86_64'
      DOWNLOAD_URL="$(printf '%s' "$API_JSON" | grep -oP '"browser_download_url":\s*"\K([^"]+)' | grep -E 'nuclei.*(linux|amd64|x86_64).*' | head -n1 || true)"
    fi

    if [[ -z "$DOWNLOAD_URL" ]]; then
      log "[-] Could not locate a suitable nuclei binary asset in release JSON."
      echo "You can provide a custom install command (recommended)."
      return 1
    fi

    log "[*] Found nuclei asset: $DOWNLOAD_URL"
    TMPDIR="$(mktemp -d)"
    cd "$TMPDIR"
    # download
    if curl -sSL -o nuclei_asset "$DOWNLOAD_URL"; then
      log "[*] Downloaded to $TMPDIR/nuclei_asset"
      # attempt extraction depending on file type
      file nuclei_asset 2>/dev/null | tee -a "$LOGFILE"
      if file nuclei_asset | grep -qi zip; then
        if command -v unzip &>/dev/null; then
          unzip -o nuclei_asset >/dev/null 2>&1 || true
        else
          log "[-] unzip missing; cannot extract zip. Please install unzip or provide custom install."
          cd - >/dev/null
          rm -rf "$TMPDIR"
          return 1
        fi
      elif file nuclei_asset | grep -qi 'gzip\|tar'; then
        tar xvf nuclei_asset >/dev/null 2>&1 || true
      else
        # might already be binary
        chmod +x nuclei_asset || true
        mv -f nuclei_asset nuclei || true
      fi

      # try to find nuclei binary in extracted files
      FOUND_BIN="$(find . -maxdepth 2 -type f -name 'nuclei' -perm /u+x -print -quit || true)"
      if [[ -z "$FOUND_BIN" ]]; then
        # try common names
        FOUND_BIN="$(find . -maxdepth 2 -type f -name 'nuclei_*' -print -quit || true)"
      fi

      if [[ -n "$FOUND_BIN" && -f "$FOUND_BIN" ]]; then
        sudo mv -f "$FOUND_BIN" /usr/local/bin/nuclei
        sudo chmod +x /usr/local/bin/nuclei
        cd - >/dev/null
        rm -rf "$TMPDIR"
        if command -v nuclei &>/dev/null; then
          log "[✓] nuclei installed to /usr/local/bin/nuclei"
          return 0
        fi
      else
        log "[-] nuclei binary not found after extraction."
        cd - >/dev/null
        rm -rf "$TMPDIR"
        return 1
      fi
    else
      log "[-] Failed to download asset from $DOWNLOAD_URL"
      cd - >/dev/null
      rm -rf "$TMPDIR"
      return 1
    fi
  else
    log "[-] curl not available; cannot download nuclei release. Provide custom install."
    return 1
  fi

  return 1
}

# run and log
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
  run_and_log "nmap" "$CMD" "$OUT.*"
  pause
}

do_nikto(){
  ensure_tool nikto "sudo apt update && sudo apt install -y nikto || true" || return
  OUT="$EVIDENCE/nikto_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="sudo nikto -h \"$TARGET\" -output \"$OUT\""
  run_and_log "nikto" "$CMD" "$OUT"
  pause
}

do_whatweb(){
  ensure_tool whatweb "sudo apt update && sudo apt install -y whatweb || true" || return
  OUT="$EVIDENCE/whatweb_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="sudo whatweb \"$TARGET\" | tee \"$OUT\""
  run_and_log "whatweb" "$CMD" "$OUT"
  pause
}

do_lynis(){
  ensure_tool lynis "sudo apt update && sudo apt install -y lynis || true" || return
  OUT="$EVIDENCE/lynis_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="sudo lynis audit system | tee \"$OUT\""
  run_and_log "lynis" "$CMD" "$OUT"
  pause
}

do_searchsploit(){
  ensure_tool searchsploit "sudo apt update && sudo apt install -y exploitdb || true" || return
  read -rp "Enter search term: " TERM
  OUT="$EVIDENCE/searchsploit_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="searchsploit \"$TERM\" | tee \"$OUT\""
  run_and_log "searchsploit" "$CMD" "$OUT"
  pause
}

do_vulners(){
  ensure_tool nmap "sudo apt update && sudo apt install -y nmap || true" || true
  # install nuclei robustly
  if command -v nuclei &>/dev/null; then
    log "[*] nuclei already available"
  else
    echo "[*] nuclei not found; attempting robust installer."
    if ! install_nuclei; then
      echo "[-] nuclei installation failed. You can install it manually and re-run this option."
      log "nuclei install failed"
    fi
  fi

  read -rp "Run nmap vuln NSE? (y/n): " r; r=${r,,}
  if [[ "$r" == "y" ]]; then
    OUT="$EVIDENCE/nmap_vuln_${SAFE_TARGET}_$(date +%H%M%S)"
    CMD="sudo nmap --script vuln -sV \"$TARGET\" -oA \"$OUT\""
    run_and_log "nmap-vuln" "$CMD" "$OUT.*"
  fi

  if command -v nuclei &>/dev/null; then
    OUT="$EVIDENCE/nuclei_${SAFE_TARGET}_$(date +%H%M%S).txt"
    CMD="echo \"$TARGET\" | sudo nuclei -silent -rate 25 -o \"$OUT\""
    run_and_log "nuclei" "$CMD" "$OUT"
  else
    echo "[!] nuclei not available; skipped nuclei run."
  fi
  pause
}

do_hash(){
  (cd "$EVIDENCE" && sha256sum * > sha256sums.txt) || true
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
