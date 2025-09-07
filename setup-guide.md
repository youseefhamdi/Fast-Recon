# BUG BOUNTY RECONNAISSANCE TOOLS MCP INTEGRATION

## Complete Setup and Installation Guide

### Prerequisites

Before setting up the MCP integration for bug bounty reconnaissance tools, ensure you have the following prerequisites installed:

#### System Requirements
- **Operating System**: Linux (Ubuntu/Debian/Kali), macOS, or Windows with WSL2
- **Python**: Version 3.9 or higher
- **Go**: Version 1.19 or higher (for Go-based tools)
- **Node.js**: Version 16 or higher (for some MCP integrations)
- **Git**: For cloning repositories

#### Essential Dependencies
```bash 
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install essential build tools
sudo apt install -y build-essential curl wget git python3 python3-pip python3-venv

# Install Go programming language
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### Tool Installation Guide 

#### 1. SUBFINDER Installation
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

#### 2. ASSETFINDER Installation
```bash
go install github.com/tomnomnom/assetfinder@latest
```

#### 3. AMASS Installation
```bash
# Method 1: Using Go
go install -v github.com/owasp-amass/amass/v4/...@master

# Method 2: Using package manager
sudo apt install amass

# Method 3: From releases
wget https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip
unzip amass_Linux_amd64.zip
sudo mv amass_Linux_amd64/amass /usr/local/bin/
```

#### 4. BBOT Installation
```bash
# Using pip
pip install bbot

# Using pipx (recommended)
pipx install bbot

# From source
git clone https://github.com/blacklanternsecurity/bbot
cd bbot
pip install .
```

#### 5. FFUF Installation
```bash
go install github.com/ffuf/ffuf/v2@latest
```

#### 6. SUBDOG Installation
```bash
git clone https://github.com/rix4uni/subdog
cd subdog
go build .
sudo mv subdog /usr/local/bin/
```

#### 7. SUDOMY Installation
```bash
git clone --recursive https://github.com/screetsec/Sudomy
cd Sudomy
pip3 install -r requirements.txt
sudo chmod +x sudomy
sudo ln -s $(pwd)/sudomy /usr/local/bin/sudomy
```

#### 8. DNSCAN Installation
```bash
git clone https://github.com/rbsec/dnscan
cd dnscan
pip install -r requirements.txt
sudo chmod +x dnscan.py
sudo ln -s $(pwd)/dnscan.py /usr/local/bin/dnscan
```

#### 9. SUBDOMAINATOR Installation
```bash
git clone https://github.com/RevoltSecurities/Subdominator
cd Subdominator
pip3 install -r requirements.txt
python3 setup.py install
```

#### 10. ASN/CIDR Tools Installation
```bash
# Install ASNmap
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest

# Install additional ASN tools
pip install ipwhois
```

### Wordlists Installation
```bash
# Install SecLists
git clone https://github.com/danielmiessler/SecLists
sudo mv SecLists /usr/share/wordlists/SecLists

# Install additional wordlists
wget https://github.com/assetnote/commonspeak2-wordlists/raw/master/subdomains/subdomains.txt
mkdir -p ~/.config/wordlists
mv subdomains.txt ~/.config/wordlists/
```

### MCP Server Setup

#### 1. Install MCP Python SDK
```bash
# Create virtual environment
python3 -m venv mcp-env
source mcp-env/bin/activate

# Install MCP SDK
pip install "mcp[cli]"
```

#### 2. Configure API Keys
Many reconnaissance tools benefit from API keys. Create a configuration file:

```bash
# Create config directory
mkdir -p ~/.config/recon-tools

# Create API configuration file
cat > ~/.config/recon-tools/api-keys.yaml << EOF
# Subfinder API Keys
subfinder:
  securitytrails: "your_securitytrails_api_key"
  censys: "your_censys_api_key"
  shodan: "your_shodan_api_key"
  virustotal: "your_virustotal_api_key"

# BBOT API Keys
bbot:
  shodan_api_key: "your_shodan_api_key"
  virustotal_api_key: "your_virustotal_api_key"

# Amass API Keys
amass:
  hunter_api_key: "your_hunter_api_key"
  censys_api_key: "your_censys_api_key"
EOF
```

#### 3. Setup Tool Configurations

**Subfinder Configuration:**
```bash
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/provider-config.yaml << EOF
securitytrails:
  - your_api_key_here
censys:
  - your_api_key_here
  - your_secret_here
shodan:
  - your_api_key_here
virustotal:
  - your_api_key_here
EOF
```

**BBOT Configuration:**
```bash
mkdir -p ~/.config/bbot
cat > ~/.config/bbot/secrets.yml << EOF
shodan_api_key: your_shodan_api_key
virustotal_api_key: your_virustotal_api_key
EOF
```

### MCP Integration Setup

#### 1. Deploy MCP Server
```bash
# Copy the MCP server code to your preferred location
mkdir -p ~/mcp-servers/recon-tools
cd ~/mcp-servers/recon-tools

# Copy the server file (assuming you have mcp_recon_server.py)
# Save the MCP server code and place it here

# Install dependencies
pip install -r requirements.txt
```

#### 2. Configure Client Integration

**For Claude Desktop:**
Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "recon-tools": {
      "command": "python",
      "args": [
        "/path/to/mcp-servers/recon-tools/mcp_recon_server.py"
      ],
      "env": {
        "PATH": "/usr/local/bin:/usr/bin:/bin"
      }
    }
  }
}
```

**For Cursor IDE:**
Add to Cursor settings:
```json
{
  "mcp.servers": [
    {
      "name": "recon-tools",
      "command": "python",
      "args": ["/path/to/mcp-servers/recon-tools/mcp_recon_server.py"]
    }
  ]
}
```

### Usage Examples

#### Basic Subdomain Enumeration
```python
# Using the MCP tools through Claude or supported client
# Example prompts:

"Use subfinder to enumerate subdomains for example.com"
"Run comprehensive reconnaissance on target.com using multiple tools"
"Perform passive enumeration only on sensitive-target.com"
```

#### Advanced Multi-tool Reconnaissance
```python
# Complex reconnaissance workflow
"Execute a complete bug bounty reconnaissance workflow:
1. Use subfinder for initial subdomain discovery
2. Run assetfinder to find related assets
3. Use amass for comprehensive enumeration
4. Validate results with httpx
5. Perform directory bruteforcing with ffuf on live subdomains"
```

### Security Considerations

1. **Rate Limiting**: Always respect target rate limits and terms of service
2. **Scope Validation**: Ensure targets are within authorized scope before scanning
3. **API Key Security**: Store API keys securely and rotate them regularly
4. **Network Monitoring**: Be aware of your network footprint when running active scans
5. **Legal Compliance**: Only use these tools on authorized targets

### Troubleshooting

#### Common Issues and Solutions

**Tool Not Found Error:**
```bash
# Add Go bin to PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

**Permission Denied:**
```bash
# Fix binary permissions
sudo chmod +x /usr/local/bin/tool_name
```

**Python Module Import Error:**
```bash
# Activate virtual environment
source mcp-env/bin/activate
pip install --upgrade mcp
```

**MCP Server Connection Issues:**
- Verify Python path in MCP configuration
- Check server logs for detailed error messages
- Ensure all tool dependencies are installed
- Validate JSON configuration syntax

### Performance Optimization

1. **Concurrent Execution**: Configure appropriate thread counts for tools
2. **Resource Management**: Monitor CPU and memory usage during large scans
3. **Result Caching**: Implement caching for frequently accessed data
4. **Tool Chaining**: Optimize tool execution order for efficiency

### Best Practices

1. **Methodology**: Always start with passive reconnaissance
2. **Documentation**: Keep detailed logs of reconnaissance activities
3. **Validation**: Verify results across multiple tools
4. **Automation**: Use the MCP integration for consistent, repeatable workflows
5. **Continuous Learning**: Stay updated with new tools and techniques

This completes the comprehensive setup guide for integrating bug bounty reconnaissance tools with the Model Context Protocol.
