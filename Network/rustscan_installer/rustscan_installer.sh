#!/bin/bash

# RustScan Installer Script for Kali Linux (No Docker)
# Author: Alvin Okiya
# Version: 2.4.1
# Last Updated: 2025-09-26

echo "[*] Starting RustScan installation..."

# Step 1: Download the .deb.zip file from GitHub
echo "[*] Downloading rustscan.deb.zip..."
wget -O rustscan.deb.zip https://github.com/bee-san/RustScan/releases/download/2.4.1/rustscan.deb.zip

# Step 2: Unzip the archive
echo "[*] Extracting rustscan.deb.zip..."
unzip rustscan.deb.zip

# Step 3: Install the .deb package
echo "[*] Installing RustScan..."
sudo dpkg -i rustscan_2.4.1-1_amd64.deb

# Step 4: Fix any broken dependencies
echo "[*] Resolving dependencies..."
sudo apt --fix-broken install -y

# Step 5: Verify installation
echo "[*] Verifying RustScan installation..."
rustscan -V

echo "[✓] RustScan installation complete."
