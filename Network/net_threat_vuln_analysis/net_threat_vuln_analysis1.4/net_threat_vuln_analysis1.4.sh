#!/usr/bin/env bash
# net_threat_vuln_analysis1.4.sh
# OpenBash Pentesting Tools - Threat modeling & Vulnerability analysis
# Version: 1.4
# Adds: automated post-nmap analysis & targeted nuclei/ssl/telnet checks
# WARNING: Run only on authorized targets.

set -euo pipefail
IFS=$'\n\t'

########## CONFIG ##########
LOGDIR="$(pwd)/logs"
mkdir -p "$LOGDIR"
LOGFILE="$LOGDIR/net_threat_vuln_$(date +%Y%m%d-%H%M%S).log"

########## HELPERS ##########
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

########## Nuclei installer (robust) ##########
install_nuclei(){
  if command -v nuclei &>/dev/null; then return 0; fi
  log "[*] nuclei not found; attempting robust installer."

  # try apt first
  if sudo apt-get update && sudo apt-get install -y nuclei >/dev/null 2>&1; then
    log "[✓] nuclei installed via apt"
    return 0
  fi
  log "[*] apt install nuclei failed or not available"

  # try GitHub release (linux amd64)
  TMPDIR=$(mktemp -d)
  pushd "$TMPDIR" >/dev/null
  log "[*] Querying GitHub for latest nuclei release..."
  if ! command -v curl &>/dev/null; then
    log "[-] curl not present; attempting apt install curl..."
    sudo apt-get update && sudo apt-get install -y curl || true
  fi
  if ! command -v unzip &>/dev/null; then
    log "[*] unzip missing; attempting apt install unzip..."
    sudo apt-get update && sudo apt-get install -y unzip || true
  fi

  API_JSON="$(curl -s -H "Accept: application/vnd.github.v3+json" https://api.github.com/repos/projectdiscovery/nuclei/releases/latest || true)"
  DOWNLOAD_URL="$(printf '%s' "$API_JSON" | grep -oP '"browser_download_url":\s*"\K([^"]+)' | grep -E 'linux.*(amd64|x86_64).*\.(zip|tar.gz|tgz|gz)' | head -n1 || true)"

  if [[ -z "$DOWNLOAD_URL" ]]; then
    log "[-] Could not find a suitable nuclei asset via GitHub API."
    popd >/dev/null
    rm -rf "$TMPDIR"
    return 1
  fi

  log "[*] Found nuclei asset: $DOWNLOAD_URL"
  if curl -sSL -o nuclei_asset "$DOWNLOAD_URL"; then
    log "[*] Downloaded nuclei asset"
  else
    log "[-] Failed to download nuclei asset"
    popd >/dev/null
    rm -rf "$TMPDIR"
    return 1
  fi

  # extract appropriate archive
  if file nuclei_asset | grep -qi zip; then
    unzip -q nuclei_asset || { log "[-] unzip failed"; popd >/dev/null; rm -rf "$TMPDIR"; return 1; }
  elif file nuclei_asset | grep -qi gzip; then
    tar xzf nuclei_asset >/dev/null 2>&1 || true
  else
    chmod +x nuclei_asset || true
    mv -f nuclei_asset nuclei || true
  fi

  # try to find nuclei binary
  FOUND_BIN="$(find . -maxdepth 3 -type f -name 'nuclei' -perm /u+x -print -quit || true)"
  if [[ -n "$FOUND_BIN" ]]; then
    sudo mv -f "$FOUND_BIN" /usr/local/bin/nuclei
    sudo chmod +x /usr/local/bin/nuclei
    log "[✓] nuclei installed to /usr/local/bin/nuclei"
    popd >/dev/null
    rm -rf "$TMPDIR"
    return 0
  fi

  log "[-] nuclei binary not found after extraction"
  popd >/dev/null
  rm -rf "$TMPDIR"
  return 1
}

########## nuclei helpers ##########
# try to update nuclei templates (supports different flags)
nuclei_update_templates(){
  if ! command -v nuclei &>/dev/null; then
    log "[-] nuclei not installed; skipping update"
    return 1
  fi

  # try common update flags
  if nuclei -update-templates >/dev/null 2>&1; then
    log "[✓] nuclei templates updated via -update-templates"
    return 0
  elif nuclei -ut >/dev/null 2>&1; then
    log "[✓] nuclei templates updated via -ut"
    return 0
  elif nuclei -update >/dev/null 2>&1; then
    log "[✓] nuclei templates updated via -update"
    return 0
  else
    log "[!] Could not auto-update nuclei templates (unknown flags)."
    return 1
  fi
}

# robust nuclei run: try with -rate then fallback
run_nuclei_targets(){
  local targets_file="$1"
  local out="$2"
  if ! command -v nuclei &>/dev/null; then
    log "[-] nuclei not installed; attempt installer"
    install_nuclei || { log "[-] nuclei unavailable, skip run"; return 1; }
  fi

  # attempt to update templates
  nuclei_update_templates || log "[*] nuclei template update skipped/failed"

  # preferred run (with -rate)
  log "[*] nuclei run: trying with -rate"
  set +e
  echo "Running nuclei (with -rate)..."
  # try -rate first
  echo "" > "$EVIDENCE/nuclei_stderr.txt" 2>/dev/null || true
  eval "cat \"$targets_file\" | sudo nuclei -silent -rate 25 -o \"$out\" 2> \"$EVIDENCE/nuclei_stderr.txt\""
  RC=$?
  set -e
  if [[ $RC -eq 0 ]]; then
    log "[✓] nuclei completed with -rate; output: $out"
    return 0
  fi

  # fallback without -rate
  log "[*] nuclei with -rate failed (rc=${RC}); falling back to run without -rate"
  set +e
  echo "" > "$EVIDENCE/nuclei_stderr2.txt" 2>/dev/null || true
  eval "cat \"$targets_file\" | sudo nuclei -silent -o \"$out\" 2> \"$EVIDENCE/nuclei_stderr2.txt\""
  RC2=$?
  set -e
  if [[ $RC2 -eq 0 ]]; then
    log "[✓] nuclei completed without -rate; output: $out"
    return 0
  fi

  log "[-] nuclei failed on both attempts (rc1=$RC rc2=$RC2). See $EVIDENCE/nuclei_stderr*.txt"
  return 2
}

########## CORE FUNCTIONS ##########
# parse most recent nmap xml in evidence dir and create targets lists and actions
analyze_nmap_and_run_followups(){
  # find latest nmap xml produced in evidence dir
  local latest_xml
  latest_xml="$(ls -1t "$EVIDENCE"/nmap_vuln_*_*.xml 2>/dev/null | head -n1 || true)"
  if [[ -z "$latest_xml" ]]; then
    log "[-] No nmap xml found for analysis. Please run nmap first."
    return 1
  fi
  log "[*] Analyzing nmap xml: $latest_xml"

  # prepare files
  local http_targets="$EVIDENCE/targets_http.txt"
  local ssl_targets="$EVIDENCE/targets_ssl.txt"
  local hostlist="$EVIDENCE/hosts_all.txt"
  : > "$http_targets"
  : > "$ssl_targets"
  : > "$hostlist"

  # prefer xmllint if available for reliable parsing
  if command -v xmllint &>/dev/null; then
    # extract hosts and open ports with service names
    xmllint --xpath '//host' "$latest_xml" > /dev/null 2>&1 || true
    # loop hosts
    local hosts
    hosts=($(xmllint --xpath 'string(//nmaprun/host/addr[1])' "$latest_xml" 2>/dev/null) || true)
    # fallback approach: parse each host element (simple)
    # Use a safer grep-based parse for wide compatibility:
    :
  fi

  # Grep-based parsing (works without xmllint)
  # For each host block, capture address and port/service entries
  awk '
    /<host>/ { inhost=1; hostblock="" }
    inhost { hostblock = hostblock $0 "\n" }
    /<\/host>/ { print hostblock; inhost=0 }
  ' "$latest_xml" | while IFS= read -r hostblk; do
    # extract address
    addr=$(printf '%s\n' "$hostblk" | grep -oP '<address addr="\K[^"]+' | head -n1 || true)
    if [[ -z "$addr" ]]; then continue; fi
    echo "$addr" >> "$hostlist"

    # find open tcp ports lines
    printf '%s\n' "$hostblk" | grep -oP '<port protocol="tcp" portid="\K[0-9]+' | while read -r port; do
      # find corresponding service name for that port (if present)
      svc=$(printf '%s\n' "$hostblk" | grep -Pzo "<port protocol=\"tcp\" portid=\"$port\">(.|\n)*?</port>" | grep -oP 'service name="\K[^"]+' | head -n1 || true)
      svc="${svc,,}"
      # classify
      if [[ "$svc" =~ http || "$port" -eq 80 || "$port" -eq 8080 || "$port" -eq 8000 ]]; then
        printf "http://%s:%s\n" "$addr" "$port" >> "$http_targets"
      elif [[ "$svc" =~ https || "$port" -eq 443 || "$port" -eq 8443 ]]; then
        printf "https://%s:%s\n" "$addr" "$port" >> "$ssl_targets"
      elif [[ "$svc" =~ telnet || "$port" -eq 23 ]]; then
        # telnet will be handled separately
        printf "%s:%s\n" "$addr" "$port" >> "$EVIDENCE/telnet_targets.txt"
      else
        # if service unknown but port is common HTTP, add heuristics
        if [[ "$port" -eq 80 || "$port" -eq 8080 || "$port" -eq 443 || "$port" -eq 8443 ]]; then
          if [[ "$port" -eq 443 || "$port" -eq 8443 ]]; then
            printf "https://%s:%s\n" "$addr" "$port" >> "$ssl_targets"
          else
            printf "http://%s:%s\n" "$addr" "$port" >> "$http_targets"
          fi
        fi
      fi
    done
  done

  # deduplicate
  sort -u -o "$http_targets" "$http_targets" 2>/dev/null || true
  sort -u -o "$ssl_targets" "$ssl_targets" 2>/dev/null || true
  sort -u -o "$hostlist" "$hostlist" 2>/dev/null || true

  log "[*] HTTP targets: $(wc -l < "$http_targets" 2>/dev/null || echo 0)"
  log "[*] SSL targets: $(wc -l < "$ssl_targets" 2>/dev/null || echo 0)"
  log "[*] Telnet targets file: $EVIDENCE/telnet_targets.txt (if any)"

  # Run ssl checks if ssl_targets exist
  if [[ -s "$ssl_targets" ]]; then
    if command -v sslscan &>/dev/null; then
      while read -r url; do
        # extract host:port
        hp=$(printf '%s' "$url" | sed -E 's#https?://##; s#/#:#g; s#(:[0-9]+).*#\1#')
        host=$(echo "$hp" | cut -d: -f1)
        port=$(echo "$hp" | cut -d: -f2)
        out="$EVIDENCE/sslscan_${host}_${port}_$(date +%H%M%S).txt"
        log "[*] Running sslscan for $host:$port -> $out"
        run_and_log "sslscan" "sudo sslscan $host:$port > \"$out\"" "$out"
      done < "$ssl_targets"
    elif [[ -f "./testssl.sh" ]]; then
      while read -r url; do
        hostport=$(echo "$url" | sed -E 's#https?://##')
        out="$EVIDENCE/testssl_${hostport//\//_}_$(date +%H%M%S).txt"
        log "[*] Running testssl.sh for $hostport -> $out"
        run_and_log "testssl.sh" "sudo ./testssl.sh --fast $hostport | tee \"$out\"" "$out"
      done < "$ssl_targets"
    else
      log "[!] No sslscan/testssl.sh available; skipping SSL deep checks."
    fi
  fi

  # Telnet banner grabs
  if [[ -f "$EVIDENCE/telnet_targets.txt" && -s "$EVIDENCE/telnet_targets.txt" ]]; then
    while read -r hp; do
      host=$(echo "$hp" | cut -d: -f1)
      port=$(echo "$hp" | cut -d: -f2)
      out="$EVIDENCE/telnet_${host}_${port}_$(date +%H%M%S).txt"
      log "[*] Grabbing telnet banner for $host:$port -> $out"
      run_and_log "telnet-banner" "sudo timeout 5 bash -c 'echo | nc -vv -w 3 $host $port' > \"$out\" 2>&1 || true" "$out"
    done < "$EVIDENCE/telnet_targets.txt"
  fi

  # Run nuclei against HTTP + SSL combined targets (if any)
  TARGETS_COMBINED="$EVIDENCE/nuclei_targets_all.txt"
  cat "$http_targets" "$ssl_targets" | sed '/^$/d' | sort -u > "$TARGETS_COMBINED"
  if [[ -s "$TARGETS_COMBINED" ]]; then
    log "[*] Prepared nuclei targets file: $TARGETS_COMBINED"
    OUT_NUC="$EVIDENCE/nuclei_${SAFE_TARGET}_$(date +%H%M%S).txt"
    run_nuclei_targets "$TARGETS_COMBINED" "$OUT_NUC" || log "[-] nuclei run returned non-zero"
  else
    log "[*] No HTTP/SSL targets detected; skipping nuclei run."
  fi

  # quick summary
  echo
  log "=== Post-nmap automated checks completed ==="
  log "Files in evidence folder:"
  ls -1 "$EVIDENCE" | sed -n '1,200p' | tee -a "$LOGFILE"
  pause
}

########## RUNNER & MENU ##########
# basic tool functions (nmap, nikto, etc.) - keep behavior from previous versions
do_nmap(){
  ensure_tool nmap "sudo apt-get update && sudo apt-get install -y nmap || true" || return
  OUT="$EVIDENCE/nmap_${SAFE_TARGET}_$(date +%H%M%S)"
  CMD="sudo nmap -sS -sV -O -T3 --script 'default,safe' \"$TARGET\" -oA \"$OUT\""
  run_and_log "nmap" "$CMD" "$OUT.*"
  pause
}

do_nikto(){
  ensure_tool nikto "sudo apt-get update && sudo apt-get install -y nikto || true" || return
  OUT="$EVIDENCE/nikto_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="sudo nikto -h \"$TARGET\" -output \"$OUT\""
  run_and_log "nikto" "$CMD" "$OUT"
  pause
}

do_whatweb(){
  ensure_tool whatweb "sudo apt-get update && sudo apt-get install -y whatweb || true" || return
  OUT="$EVIDENCE/whatweb_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="sudo whatweb \"$TARGET\" | tee \"$OUT\""
  run_and_log "whatweb" "$CMD" "$OUT"
  pause
}

do_lynis(){
  ensure_tool lynis "sudo apt-get update && sudo apt-get install -y lynis || true" || return
  OUT="$EVIDENCE/lynis_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="sudo lynis audit system | tee \"$OUT\""
  run_and_log "lynis" "$CMD" "$OUT"
  pause
}

do_searchsploit(){
  ensure_tool searchsploit "sudo apt-get update && sudo apt-get install -y exploitdb || true" || return
  read -rp "Enter search term: " TERM
  OUT="$EVIDENCE/searchsploit_${SAFE_TARGET}_$(date +%H%M%S).txt"
  CMD="searchsploit \"$TERM\" | tee \"$OUT\""
  run_and_log "searchsploit" "$CMD" "$OUT"
  pause
}

do_vulners(){
  # run nmap vuln script first (non-destructive default), then run automated followups
  ensure_tool nmap "sudo apt-get update && sudo apt-get install -y nmap || true" || true
  OUT="$EVIDENCE/nmap_vuln_${SAFE_TARGET}_$(date +%H%M%S)"
  CMD="sudo nmap --script vuln -sV \"$TARGET\" -oA \"$OUT\""
  run_and_log "nmap-vuln" "$CMD" "$OUT.*"

  # after nmap completes, run analysis automation (nuclei, ssl, telnet banners)
  analyze_nmap_and_run_followups
  pause
}

do_hash(){
  (cd "$EVIDENCE" && sha256sum * > sha256sums.txt) || true
  echo "Hashes saved in $EVIDENCE/sha256sums.txt"
  pause
}

########## SCRIPT START ##########
clear
cat <<'EOF'
==================================================================
  OpenBash Pentesting Tools - Threat modeling & Vulnerability analysis
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

read -rp "Enter target (IP, CIDR, range, or domain): " TARGET
SAFE_TARGET=$(sanitize "$TARGET")
EVIDENCE="Evidence/${SAFE_TARGET}/$(date +%Y-%m-%d)/threat_analysis"
mkdir -p "$EVIDENCE"
log "Target: $TARGET"
log "Evidence dir: $EVIDENCE"
pause

# Main menu
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
6) Vulners (nmap NSE + automated follow-ups)
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
    9) echo "Exiting..."; exit 0 ;;
    *) echo "Invalid option"; pause ;;
  esac
done
