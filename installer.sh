#!/bin/bash

# installer.sh - Installs dependencies and tools for xsql.py
# Usage: chmod +x installer.sh && ./installer.sh

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root (for package installations)
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}Please do not run as root. Run as a regular user with sudo privileges if needed.${NC}"
    exit 1
fi

# Check for required commands
check_command() {
    command -v "$1" >/dev/null 2>&1 || { echo -e "${RED}$1 is required but not installed. Exiting.${NC}"; exit 1; }
}

echo -e "${YELLOW}[*] Checking for required system tools...${NC}"
for cmd in go curl python3 pip3 sudo; do
    check_command "$cmd"
done
echo -e "${GREEN}[+] All required system tools are present.${NC}"

# Install Python dependencies
echo -e "${YELLOW}[*] Setting up Python virtual environment...${NC}"
python3 -m venv venv || { echo -e "${RED}Failed to create virtual environment.${NC}"; exit 1; }
source venv/bin/activate
if [ -f requirements.txt ]; then
    echo -e "${YELLOW}[*] Installing Python dependencies from requirements.txt...${NC}"
    pip install --upgrade pip
    pip install -r requirements.txt || { echo -e "${RED}Failed to install Python dependencies.${NC}"; exit 1; }
    echo -e "${GREEN}[+] Python dependencies installed.${NC}"
else
    echo -e "${RED}requirements.txt not found. Please ensure it exists in the current directory.${NC}"
    exit 1
fi

# Function to check and install a Go tool
install_go_tool() {
    local tool_name="$1"
    local tool_repo="$2"
    if command -v "$tool_name" >/dev/null 2>&1; then
        echo -e "${GREEN}[+] $tool_name is already installed.${NC}"
    else
        echo -e "${YELLOW}[*] Installing $tool_name...${NC}"
        GO111MODULE=on go install "$tool_repo@latest" || { echo -e "${RED}Failed to install $tool_name.${NC}"; exit 1; }
        echo -e "${GREEN}[+] $tool_name installed.${NC}"
    fi
}

# Install Go-based tools
echo -e "${YELLOW}[*] Installing Go-based tools...${NC}"
install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder"
install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx"
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana"
install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls"
install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau"
install_go_tool "uro" "github.com/s0md3v/uro"
install_go_tool "anew" "github.com/tomnomnom/anew"

# Install findomain
if command -v findomain >/dev/null 2>&1; then
    echo -e "${GREEN}[+] findomain is already installed.${NC}"
else
    echo -e "${YELLOW}[*] Installing findomain...${NC}"
    if [[ "$(uname)" == "Linux" ]]; then
        curl -sLO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux
        chmod +x findomain-linux
        sudo mv findomain-linux /usr/local/bin/findomain || { echo -e "${RED}Failed to install findomain.${NC}"; exit 1; }
        echo -e "${GREEN}[+] findomain installed.${NC}"
    else
        echo -e "${RED}findomain installation is only automated for Linux. Please install manually for your OS.${NC}"
        exit 1
    fi
fi

# Verify installations
echo -e "${YELLOW}[*] Verifying tool installations...${NC}"
for tool in subfinder assetfinder findomain dnsx httpx katana waybackurls gau uro anew; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "${GREEN}[+] $tool is installed and accessible.${NC}"
    else
        echo -e "${RED}[-] $tool is not installed or not in PATH. Please check installation.${NC}"
        exit 1
    fi
done

# Deactivate virtual environment
deactivate

echo -e "${GREEN}[+] Installation completed successfully!${NC}"
echo -e "${YELLOW}[*] To use xsql.py, activate the virtual environment:${NC}"
echo -e "${YELLOW}    source venv/bin/activate${NC}"
echo -e "${YELLOW}[*] Then run xsql.py, e.g.:${NC}"
echo -e "${YELLOW}    python3 xsql.py -d example.com --live --subdomains --test-both --test-waf-urls --debug${NC}"
