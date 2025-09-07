#!/bin/bash
# Bug Bounty Recon Tools Installation Script
# Installs all reconnaissance tools for MCP integration

echo "Installing Bug Bounty Recon Tools for MCP Integration..."

# Update system packages
sudo apt update

# Install Go (required for many tools)
if ! command -v go &> /dev/null; then
    echo "Installing Go..."
    wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
fi

# Install Python and pip
sudo apt install -y python3 python3-pip

# Install FastMCP
echo "Installing FastMCP..."
pip3 install fastmcp

# Install Go-based tools
echo "Installing Go-based reconnaissance tools..."

# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Assetfinder
go install github.com/tomnomnom/assetfinder@latest

# Amass
go install -v github.com/OWASP/Amass/v3/...@master

# FFUF
go install github.com/ffuf/ffuf@latest

# ASNMap
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest

# Install Python-based tools
echo "Installing Python-based tools..."

# BBOT
python3 -m pip install bbot

# Install other tools from GitHub
echo "Installing tools from GitHub..."

# Sudomy
git clone https://github.com/screetsec/Sudomy.git /opt/Sudomy
sudo chmod +x /opt/Sudomy/sudomy
sudo ln -sf /opt/Sudomy/sudomy /usr/local/bin/sudomy

# Dnscan
git clone https://github.com/rbsec/dnscan.git /opt/dnscan
pip3 install -r /opt/dnscan/requirements.txt
sudo ln -sf /opt/dnscan/dnscan.py /usr/local/bin/dnscan

# Subdomainator (download binary)
wget -O /tmp/Subdomainator https://github.com/Stratus-Security/Subdominator/releases/latest/download/Subdomainator
sudo chmod +x /tmp/Subdomainator
sudo mv /tmp/Subdomainator /usr/local/bin/

# Ensure Go binaries are in PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

echo "Installation completed!"
echo "Run 'python3 recon-mcp-server.py' to start the MCP server"