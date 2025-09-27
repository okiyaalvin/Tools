#!/bin/bash
# net_recon_helper1.2.sh
# OpenBash Pentesting Tools - Network Recon Helper
# Author: Your Pentest Team
# Disclaimer: For authorized security testing only.

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

######################
#      Disclaimer    #
######################

clear
echo "=============================================================="
echo "   OpenBash Pentesting Tools - Network Recon Helper v1.2"
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

read -p "Do you have a signed Rules of Engagement? (y/n): " roe
check_exit "$roe"

read -p "Do you have a signed Client Consent? (y/n): " consent
check_exit "$consent"

read -p "Do you have a Scope of Work document? (y/n): " sow
check_exit "$sow"

read -p "Do you have an NDA signed? (y/n): " nda
check_exit "$nda"

echo "[+] All authorization documents confirmed."
pause

######################
#   Scope Selection  #
######################

while true; do
  clear
  echo ">>> Step 2: Define Target Scope"
  echo "Select target type:"
  echo "  1) Public IP"
  echo "  2) IP Range"
  echo "  3) Subnet (CIDR, e.g. 192.168.1.0/24)"
  echo "  4) Domain name"
  echo "  5) Back"
  echo "  0) Exit"
  echo

  read -p "Enter your choice: " scope_choice

  case $scope_choice in
    1) read -p "Enter Public IP: " target;;
    2) read -p "Enter IP Range (e.g. 192.168.1.1-192.168.1.50): " target;;
    3) read -p "Enter Subnet (CIDR, e.g. 192.168.1.0/24): " target;;
    4) read -p "Enter Domain (e.g. example.com): " target;;
    5) continue;;
    0) echo "Exiting..."; exit 0;;
    *) echo "Invalid option"; pause; continue;;
  esac
  break
done

######################
#   Recon Menu       #
######################

while true; do
  clear
  echo ">>> Step 3: Reconnaissance Menu"
  echo "Target: $target"
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
      echo "  1) Subfinder (fast subdomain discovery)"
      echo "  2) Amass (comprehensive OSINT)"
      echo "  3) TheHarvester (emails & subdomains)"
      echo "  9) Back"
      echo "  0) Exit"
      read -p "Choice: " passive_choice
      case $passive_choice in
        1) subfinder -d "$target" -silent -o subfinder_$target.txt ;;
        2) amass enum -passive -d "$target" -o amass_$target.txt ;;
        3) theHarvester -d "$target" -b all -l 500 -f harvester_$target.html ;;
        9) continue ;;
        0) exit 0 ;;
        *) echo "Invalid option";;
      esac
      pause
      ;;
    2)
      clear
      echo "DNS Enumeration Options:"
      echo "  1) dnsrecon"
      echo "  2) dnsenum"
      echo "  3) dig (AXFR test)"
      echo "  9) Back"
      echo "  0) Exit"
      read -p "Choice: " dns_choice
      case $dns_choice in
        1) dnsrecon -d "$target" -t std -a -n 8.8.8.8 -o dnsrecon_$target.txt ;;
        2) dnsenum --enum "$target" -o dnsenum_$target.txt ;;
        3) dig @ns1."$target" "$target" AXFR > dig_axfr_$target.txt ;;
        9) continue ;;
        0) exit 0 ;;
        *) echo "Invalid option";;
      esac
      pause
      ;;
    3)
      clear
      echo "Network Discovery Options:"
      echo "  1) fping sweep"
      echo "  2) masscan (fast)"
      echo "  3) naabu"
      echo "  9) Back"
      echo "  0) Exit"
      read -p "Choice: " net_choice
      case $net_choice in
        1) fping -a -g "$target" 2>/dev/null > fping_$target.txt ;;
        2) masscan "$target" -p1-65535 --rate=1000 -oL masscan_$target.txt ;;
        3) naabu -host "$target" -silent -o naabu_$target.txt ;;
        9) continue ;;
        0) exit 0 ;;
        *) echo "Invalid option";;
      esac
      pause
      ;;
    4)
      clear
      echo "Service Fingerprinting Options:"
      echo "  1) nmap (service/version detection)"
      echo "  2) httpx (web probing)"
      echo "  3) sslscan"
      echo "  9) Back"
      echo "  0) Exit"
      read -p "Choice: " svc_choice
      case $svc_choice in
        1) nmap -sV -T3 -Pn "$target" -oA nmap_$target ;;
        2) echo "$target" | httpx -silent -title -status-code -o httpx_$target.txt ;;
        3) sslscan "$target" > sslscan_$target.txt ;;
        9) continue ;;
        0) exit 0 ;;
        *) echo "Invalid option";;
      esac
      pause
      ;;
    5)
      clear
      echo "Vulnerability Enumeration Options:"
      echo "  1) nuclei"
      echo "  2) nikto"
      echo "  3) nmap NSE (vuln)"
      echo "  9) Back"
      echo "  0) Exit"
      read -p "Choice: " vuln_choice
      case $vuln_choice in
        1) nuclei -u "$target" -rate 20 -o nuclei_$target.txt ;;
        2) nikto -h "$target" -output nikto_$target.txt ;;
        3) nmap --script vuln -sV "$target" -oA nmap_vuln_$target ;;
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
