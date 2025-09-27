#!/usr/bin/env bash
# net_threat_vuln_analysis1.5.sh
# Phase: Threat Modeling & Vulnerability Analysis (PTES)
# Author: Revoltcipher (patched by ChatGPT)
# Version: 1.5 (fixed ensure_tool command quoting)

set -euo pipefail

# ================== CONFIG ==================
TARGET_IP=""
EVIDENCE_DIR=""
DATE=$(date +%F)
LOG_DIR="logs"
mkdir -p "$LOG_DIR"

log() {
    echo "[$(date '+%F %T')] $*" | tee -a "$LOG_DIR/net_threat_vuln_${DATE}.log"
}

pause() {
    read -rp "Press Enter to continue..."
}

# ================== TOOL CHECKER ==================
ensure_tool() {
    local tool=$1
    local install_cmd=$2

    if ! command -v "$tool" &>/dev/null; then
        log "[-] Tool '$tool' not found."
        read -rp "Press Enter to install with default command [$install_cmd], or type custom command: " custom_cmd
        if [[ -n "$custom_cmd" ]]; then
            eval "$custom_cmd"
        else
            eval "$install_cmd"
        fi
    fi

    if ! command -v "$tool" &>/dev/null; then
        log "[!] '$tool' still missing after install attempt."
        return 1
    fi

    return 0
}

# ================== SETUP ==================
setup_target() {
    read -rp "Enter target IP/domain: " TARGET_IP
    if [[ -z "$TARGET_IP" ]]; then
        echo "[!] Target cannot be empty"
        exit 1
    fi
    EVIDENCE_DIR="Evidence/$TARGET_IP/$DATE/threat_analysis"
    mkdir -p "$EVIDENCE_DIR"
    log "[*] Evidence directory: $EVIDENCE_DIR"
}

# ================== FUNCTIONS ==================
do_nmap() {
    ensure_tool nmap 'sudo apt-get update && sudo apt-get install -y nmap || true'
    local out="$EVIDENCE_DIR/nmap_${TARGET_IP}_$(date +%H%M%S)"
    log "EXEC | Tool: nmap | Cmd: sudo nmap -A -sV \"$TARGET_IP\" -oA \"$out\""
    sudo nmap -A -sV "$TARGET_IP" -oA "$out"
}

do_nikto() {
    ensure_tool nikto 'sudo apt-get update && sudo apt-get install -y nikto || true'
    local out="$EVIDENCE_DIR/nikto_${TARGET_IP}_$(date +%H%M%S).txt"
    log "EXEC | Tool: nikto | Cmd: nikto -h \"$TARGET_IP\" -output \"$out\""
    nikto -h "$TARGET_IP" -output "$out"
}

do_whatweb() {
    ensure_tool whatweb 'sudo apt-get update && sudo apt-get install -y whatweb || true'
    local out="$EVIDENCE_DIR/whatweb_${TARGET_IP}_$(date +%H%M%S).txt"
    log "EXEC | Tool: whatweb | Cmd: whatweb \"$TARGET_IP\" > \"$out\""
    whatweb "$TARGET_IP" > "$out"
}

do_lynis() {
    ensure_tool lynis 'sudo apt-get update && sudo apt-get install -y lynis || true'
    local out="$EVIDENCE_DIR/lynis_${TARGET_IP}_$(date +%H%M%S).txt"
    log "EXEC | Tool: lynis | Cmd: sudo lynis audit system > \"$out\""
    sudo lynis audit system > "$out"
}

do_searchsploit() {
    ensure_tool searchsploit 'sudo apt-get update && sudo apt-get install -y exploitdb || true'
    local out="$EVIDENCE_DIR/searchsploit_${TARGET_IP}_$(date +%H%M%S).txt"
    log "EXEC | Tool: searchsploit | Cmd: searchsploit \"$TARGET_IP\" > \"$out\""
    searchsploit "$TARGET_IP" > "$out"
}

do_vulners() {
    ensure_tool nmap 'sudo apt-get update && sudo apt-get install -y nmap || true'
    ensure_tool nuclei 'sudo apt-get update && sudo apt-get install -y nuclei || true'

    log "[*] nuclei detected at: $(command -v nuclei)"
    nuclei -version 2>&1 | tee -a "$LOG_DIR/net_threat_vuln_${DATE}.log"

    read -rp "Run nmap vuln NSE? (y/n): " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        local out="$EVIDENCE_DIR/nmap_vuln_${TARGET_IP}_$(date +%H%M%S)"
        log "EXEC | Tool: nmap-vuln | Cmd: sudo nmap --script vuln -sV \"$TARGET_IP\" -oA \"$out\""
        sudo nmap --script vuln -sV "$TARGET_IP" -oA "$out"
    fi

    local nuclei_out="$EVIDENCE_DIR/nuclei_${TARGET_IP}_$(date +%H%M%S).txt"
    log "[*] Attempting nuclei scan..."
    if ! echo "$TARGET_IP" | nuclei -silent -o "$nuclei_out"; then
        log "[!] nuclei scan failed"
    else
        log "[✓] nuclei results saved: $nuclei_out"
    fi
}

do_hash() {
    log "[*] Generating SHA256 hashes for evidence..."
    (cd "$EVIDENCE_DIR" && sha256sum * > SHA256SUMS.txt)
    log "[✓] Hashes stored in $EVIDENCE_DIR/SHA256SUMS.txt"
}

# ================== MENU ==================
menu() {
    while true; do
        clear
        echo "Threat modeling & Vulnerability analysis"
        echo "Target: $TARGET_IP"
        echo "Evidence: $EVIDENCE_DIR"
        echo
        cat <<EOF
1) Nmap (fingerprint + NSE)
2) Nikto (web checks)
3) WhatWeb (stack ID)
4) Lynis (hardening)
5) Searchsploit
6) Vulners (nmap NSE + nuclei)
7) Hash evidence
9) Exit
EOF
        read -rp "Select [1-9]: " choice
        case $choice in
            1) do_nmap ;;
            2) do_nikto ;;
            3) do_whatweb ;;
            4) do_lynis ;;
            5) do_searchsploit ;;
            6) do_vulners ;;
            7) do_hash ;;
            9) exit 0 ;;
            *) echo "Invalid choice"; pause ;;
        esac
        pause
    done
}

# ================== MAIN ==================
setup_target
menu
