#!/usr/bin/env bash
set -e

# 1) Make sure system packages are up to date
sudo apt-get update

# 2) Install Python 3 and venv if not already installed
sudo apt-get install -y python3 python3-venv

# 3) Create a system-wide directory (owned by root) for the marimo venv
sudo mkdir -p /opt/marimo
sudo chown $USER:$USER /opt/marimo

# 4) Create a virtual environment in /opt/marimo
python3 -m venv /opt/marimo

# 5) Upgrade pip in that venv and install Marimo
/opt/marimo/bin/pip install --upgrade pip
/opt/marimo/bin/pip install marimo

# 6) Symlink the 'marimo' executable to /usr/local/bin so it's on your PATH
sudo ln -sf /opt/marimo/bin/marimo /usr/local/bin/marimo

echo "======================================================="
echo "Marimo installed in /opt/marimo and symlinked to /usr/local/bin"
echo "You can now run 'marimo' from any directory."
echo "======================================================="


