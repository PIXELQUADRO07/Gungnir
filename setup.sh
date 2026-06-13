#!/bin/bash

# Gungnir dependency setup script for Debian/Ubuntu
# Usage: sudo ./setup.sh

set -e

echo "[+] Updating package list..."
sudo apt-get update -y

echo "[+] Installing core dependencies..."
sudo apt-get install -y \
    build-essential \
    cmake \
    libcurl4-openssl-dev \
    libsqlite3-dev \
    libreadline-dev \
    nmap \
    exploitdb \
    chromium-browser

echo "[+] Success! Gungnir dependencies installed."
echo "[+] You can now build the project with:"
echo "    cmake -B build && cmake --build build"
