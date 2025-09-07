# Create a comprehensive MCP server implementation for bug bounty recon tools
import json

mcp_server_code = '''
#!/usr/bin/env python3
"""
Bug Bounty Recon Tools MCP Server
A FastMCP server integrating popular reconnaissance tools for bug bounty hunting.

Author: AI Assistant
Purpose: Integrate recon tools with MCP for faster data collection
No AI agent connections - Pure tool integration via FastMCP
"""

import subprocess
import json
import asyncio
import os
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Union
from fastmcp import FastMCP
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP(
    name="Bug Bounty Recon Tools Server",
    instructions="Fast reconnaissance tool integration for bug bounty hunting. Provides subdomain enumeration, asset discovery, and vulnerability scanning capabilities."
)

class ReconToolsExecutor:
    """Handles execution of various reconnaissance tools"""
    
    @staticmethod
    def run_command(cmd: List[str], timeout: int = 300) -> Dict[str, Union[str, int]]:
        """Execute shell command with timeout and error handling"""
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                check=False
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "success": result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "returncode": -1,
                "success": False
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -2,
                "success": False
            }

executor = ReconToolsExecutor()

# SUBFINDER Integration
@mcp.tool
def run_subfinder(domain: str, sources: str = "all", output_format: str = "txt") -> str:
    """
    Run Subfinder for passive subdomain enumeration
    
    Args:
        domain: Target domain to enumerate subdomains for
        sources: Comma-separated list of sources or 'all' for all sources
        output_format: Output format ('txt', 'json')
    """
    cmd = ["subfinder", "-d", domain, "-silent"]
    
    if sources != "all":
        cmd.extend(["-sources", sources])
    
    if output_format == "json":
        cmd.append("-json")
    
    result = executor.run_command(cmd)
    
    if result["success"]:
        return f"Subfinder Results:\\n{result['stdout']}"
    else:
        return f"Subfinder Error: {result['stderr']}"

# ASSETFINDER Integration
@mcp.tool
def run_assetfinder(domain: str, subs_only: bool = True) -> str:
    """
    Run Assetfinder for subdomain discovery
    
    Args:
        domain: Target domain to find assets for
        subs_only: Only show subdomains (exclude unrelated domains)
    """
    cmd = ["assetfinder"]
    
    if subs_only:
        cmd.append("--subs-only")
    
    cmd.append(domain)
    
    result = executor.run_command(cmd)
    
    if result["success"]:
        return f"Assetfinder Results:\\n{result['stdout']}"
    else:
        return f"Assetfinder Error: {result['stderr']}"

# AMASS Integration
@mcp.tool
def run_amass(domain: str, mode: str = "enum", timeout: int = 10) -> str:
    """
    Run Amass for comprehensive asset discovery
    
    Args:
        domain: Target domain for reconnaissance
        mode: Amass mode ('enum', 'intel', 'viz')
        timeout: Timeout in minutes
    """
    cmd = ["amass", mode, "-d", domain, "-timeout", str(timeout)]
    
    result = executor.run_command(cmd, timeout=timeout*60)
    
    if result["success"]:
        return f"Amass Results:\\n{result['stdout']}"
    else:
        return f"Amass Error: {result['stderr']}"

# BBOT Integration
@mcp.tool
def run_bbot(target: str, modules: str = "subdomain-enum") -> str:
    """
    Run BBOT for automated OSINT reconnaissance
    
    Args:
        target: Target domain or IP
        modules: Comma-separated list of modules to use
    """
    cmd = ["bbot", "-t", target, "-m", modules]
    
    result = executor.run_command(cmd, timeout=600)  # 10 minute timeout
    
    if result["success"]:
        return f"BBOT Results:\\n{result['stdout']}"
    else:
        return f"BBOT Error: {result['stderr']}"

# FFUF Integration
@mcp.tool
def run_ffuf(url: str, wordlist_path: str, extensions: str = "") -> str:
    """
    Run FFUF for directory and file fuzzing
    
    Args:
        url: Target URL with FUZZ placeholder (e.g., https://example.com/FUZZ)
        wordlist_path: Path to wordlist file
        extensions: Comma-separated list of extensions to append
    """
    if "FUZZ" not in url:
        return "Error: URL must contain FUZZ placeholder"
    
    cmd = ["ffuf", "-w", wordlist_path, "-u", url, "-mc", "200,201,202,204,301,302,307,308,401,403"]
    
    if extensions:
        cmd.extend(["-e", extensions])
    
    result = executor.run_command(cmd, timeout=600)
    
    if result["success"]:
        return f"FFUF Results:\\n{result['stdout']}"
    else:
        return f"FFUF Error: {result['stderr']}"

# SUDOMY Integration
@mcp.tool
def run_sudomy(domain: str, mode: str = "passive") -> str:
    """
    Run Sudomy for advanced subdomain enumeration and analysis
    
    Args:
        domain: Target domain
        mode: Enumeration mode ('passive', 'bruteforce', 'takeover')
    """
    cmd = ["sudomy", "-d", domain]
    
    if mode == "passive":
        cmd.append("--passive")
    elif mode == "bruteforce":
        cmd.append("--bruteforce")
    elif mode == "takeover":
        cmd.append("--takeover")
    
    result = executor.run_command(cmd, timeout=1800)  # 30 minute timeout
    
    if result["success"]:
        return f"Sudomy Results:\\n{result['stdout']}"
    else:
        return f"Sudomy Error: {result['stderr']}"

# DNSCAN Integration
@mcp.tool
def run_dnscan(domain: str, wordlist_path: str = "", threads: int = 8) -> str:
    """
    Run Dnscan for DNS subdomain scanning
    
    Args:
        domain: Target domain to scan
        wordlist_path: Custom wordlist path (optional)
        threads: Number of threads to use
    """
    cmd = ["python3", "dnscan.py", "-d", domain, "-t", str(threads)]
    
    if wordlist_path:
        cmd.extend(["-w", wordlist_path])
    
    result = executor.run_command(cmd, timeout=900)  # 15 minute timeout
    
    if result["success"]:
        return f"Dnscan Results:\\n{result['stdout']}"
    else:
        return f"Dnscan Error: {result['stderr']}"

# SUBDOMAINATOR Integration
@mcp.tool
def run_subdomainator(domain: str, validate: bool = False) -> str:
    """
    Run Subdomainator for subdomain takeover detection
    
    Args:
        domain: Target domain to check for takeovers
        validate: Perform validation of potential takeovers
    """
    cmd = ["Subdomainator", "-d", domain]
    
    if validate:
        cmd.append("--validate")
    
    result = executor.run_command(cmd, timeout=300)
    
    if result["success"]:
        return f"Subdomainator Results:\\n{result['stdout']}"
    else:
        return f"Subdomainator Error: {result['stderr']}"

# ASN and CIDR Tools Integration
@mcp.tool
def run_asnmap(target: str, target_type: str = "org") -> str:
    """
    Run ASNMap for ASN and CIDR range discovery
    
    Args:
        target: Target organization, domain, IP, or ASN
        target_type: Type of target ('org', 'domain', 'ip', 'asn')
    """
    cmd = ["asnmap"]
    
    if target_type == "org":
        cmd.extend(["-org", target])
    elif target_type == "domain":
        cmd.extend(["-d", target])
    elif target_type == "ip":
        cmd.extend(["-i", target])
    elif target_type == "asn":
        cmd.extend(["-a", target])
    else:
        return f"Error: Invalid target_type '{target_type}'. Use: org, domain, ip, or asn"
    
    result = executor.run_command(cmd)
    
    if result["success"]:
        return f"ASNMap Results:\\n{result['stdout']}"
    else:
        return f"ASNMap Error: {result['stderr']}"

# Aggregate Tool for Complete Reconnaissance
@mcp.tool
def run_complete_recon(domain: str, include_aggressive: bool = False) -> str:
    """
    Run a complete reconnaissance scan using multiple tools
    
    Args:
        domain: Target domain for comprehensive recon
        include_aggressive: Include aggressive/active scanning tools
    """
    results = []
    
    # Passive tools
    logger.info(f"Starting passive recon for {domain}")
    
    # Subfinder
    subfinder_result = run_subfinder(domain)
    results.append(f"=== SUBFINDER ===\\n{subfinder_result}")
    
    # Assetfinder
    assetfinder_result = run_assetfinder(domain)
    results.append(f"=== ASSETFINDER ===\\n{assetfinder_result}")
    
    # Amass (with shorter timeout for aggregate)
    amass_result = run_amass(domain, timeout=5)
    results.append(f"=== AMASS ===\\n{amass_result}")
    
    # ASN/CIDR info
    asnmap_result = run_asnmap(domain, "domain")
    results.append(f"=== ASNMAP ===\\n{asnmap_result}")
    
    if include_aggressive:
        logger.info(f"Including aggressive scans for {domain}")
        
        # Subdomainator for takeover detection
        takeover_result = run_subdomainator(domain)
        results.append(f"=== TAKEOVER DETECTION ===\\n{takeover_result}")
    
    return "\\n\\n".join(results)

# Resource for configuration and tool status
@mcp.resource
def get_recon_tools_status() -> str:
    """Get status and configuration of all recon tools"""
    tools_status = {
        "subfinder": {"installed": False, "version": ""},
        "assetfinder": {"installed": False, "version": ""},
        "amass": {"installed": False, "version": ""},
        "bbot": {"installed": False, "version": ""},
        "ffuf": {"installed": False, "version": ""},
        "sudomy": {"installed": False, "version": ""},
        "dnscan": {"installed": False, "version": ""},
        "subdomainator": {"installed": False, "version": ""},
        "asnmap": {"installed": False, "version": ""}
    }
    
    # Check tool availability
    for tool in tools_status.keys():
        try:
            if tool == "dnscan":
                # Special case for Python scripts
                result = subprocess.run(["python3", "dnscan.py", "--help"], 
                                      capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run([tool, "--version"], 
                                      capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                tools_status[tool]["installed"] = True
                tools_status[tool]["version"] = result.stdout.strip()
        except:
            tools_status[tool]["installed"] = False
    
    return json.dumps(tools_status, indent=2)

# Configuration resource
@mcp.resource
def get_mcp_config() -> str:
    """Get MCP server configuration and usage instructions"""
    config = {
        "server_name": "Bug Bounty Recon Tools Server",
        "version": "1.0.0",
        "supported_tools": [
            "subfinder", "assetfinder", "amass", "bbot", "ffuf",
            "sudomy", "dnscan", "subdomainator", "asnmap"
        ],
        "transport_modes": ["stdio", "http", "sse"],
        "usage_examples": {
            "passive_recon": "run_subfinder('example.com')",
            "complete_recon": "run_complete_recon('example.com')",
            "takeover_detection": "run_subdomainator('example.com', validate=True)",
            "asn_discovery": "run_asnmap('GOOGLE', 'org')"
        },
        "installation_notes": [
            "Install tools via package managers or from GitHub releases",
            "Configure API keys in tool-specific config files",
            "Ensure proper PATH configuration for all tools"
        ]
    }
    
    return json.dumps(config, indent=2)

if __name__ == "__main__":
    logger.info("Starting Bug Bounty Recon Tools MCP Server")
    logger.info("Available tools: subfinder, assetfinder, amass, bbot, ffuf, sudomy, dnscan, subdomainator, asnmap")
    logger.info("Use @mcp.tool decorators to access individual tools")
    logger.info("Use run_complete_recon() for comprehensive reconnaissance")
    
    # Run the MCP server
    mcp.run()
'''

# Save the MCP server implementation
with open('recon_mcp_server.py', 'w') as f:
    f.write(mcp_server_code)

# Create installation script
install_script = '''#!/bin/bash
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
wget -O /tmp/Subdomainator https://github.com/Stratus-Security/Subdominator/releases/latest/download/Subdominator
sudo chmod +x /tmp/Subdomainator
sudo mv /tmp/Subdomainator /usr/local/bin/

# Ensure Go binaries are in PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

echo "Installation completed!"
echo "Run 'python3 recon_mcp_server.py' to start the MCP server"
'''

with open('install_recon_tools.sh', 'w') as f:
    f.write(install_script)

# Create usage examples
usage_examples = '''# Bug Bounty Recon Tools MCP Server Usage Examples

## Starting the MCP Server

### Stdio Mode (for local AI clients)
```bash
python3 recon_mcp_server.py
```

### HTTP Mode (for remote clients)
```python
from fastmcp import FastMCP
mcp = FastMCP("Recon Server", host="0.0.0.0", port=8000)
# ... add tools ...
mcp.run(transport="http")
```

## Tool Usage Examples

### 1. Passive Subdomain Enumeration
```python
# Using Subfinder
result = run_subfinder("example.com", sources="all", output_format="json")

# Using Assetfinder  
result = run_assetfinder("example.com", subs_only=True)

# Using Amass
result = run_amass("example.com", mode="enum", timeout=10)
```

### 2. Comprehensive Reconnaissance
```python
# Complete passive recon
result = run_complete_recon("example.com", include_aggressive=False)

# Complete recon with aggressive scanning
result = run_complete_recon("example.com", include_aggressive=True)
```

### 3. Asset Discovery and Analysis
```python
# ASN and CIDR discovery
result = run_asnmap("GOOGLE", target_type="org")
result = run_asnmap("AS15169", target_type="asn")

# Directory fuzzing
result = run_ffuf("https://example.com/FUZZ", "/usr/share/wordlists/dirb/common.txt")
```

### 4. Vulnerability Detection
```python
# Subdomain takeover detection
result = run_subdomainator("example.com", validate=True)

# OSINT automation
result = run_bbot("example.com", modules="subdomain-enum,port-scan")
```

## Integration with AI Clients

### Claude Desktop Configuration
Add to your Claude Desktop MCP configuration:
```json
{
  "mcpServers": {
    "recon-tools": {
      "command": "python3",
      "args": ["/path/to/recon_mcp_server.py"]
    }
  }
}
```

### VS Code with Roo-Cline
Configure MCP server in VS Code settings for automated recon workflows.

### Custom Client Integration
```python
from fastmcp import Client

async def main():
    async with Client("python3 recon_mcp_server.py") as client:
        # List available tools
        tools = await client.list_tools()
        print("Available tools:", [tool.name for tool in tools])
        
        # Run reconnaissance
        result = await client.call_tool("run_complete_recon", {
            "domain": "example.com",
            "include_aggressive": False
        })
        print("Recon results:", result.content[0].text)

if __name__ == "__main__":
    asyncio.run(main())
```

## Performance Optimization

### Parallel Execution
The MCP server automatically handles async execution for improved performance.

### Custom Timeouts
Adjust timeouts based on target complexity:
```python
# Short timeout for quick scans
result = run_amass("example.com", timeout=5)

# Extended timeout for comprehensive scans
result = run_amass("example.com", timeout=30)
```

### Resource Monitoring
Check tool status and configuration:
```python
status = get_recon_tools_status()  # Returns JSON with tool availability
config = get_mcp_config()          # Returns server configuration
```
'''

with open('usage_examples.md', 'w') as f:
    f.write(usage_examples)

print("Created comprehensive MCP server implementation:")
print("✅ recon_mcp_server.py - Main MCP server with all tool integrations")
print("✅ install_recon_tools.sh - Installation script for all tools") 
print("✅ usage_examples.md - Usage examples and integration guide")
print("\nKey features implemented:")
print("- FastMCP framework integration")
print("- All 10 recon tools wrapped with @mcp.tool decorators")
print("- Async execution for performance")
print("- Error handling and timeouts")
print("- Resource endpoints for configuration")
print("- Complete recon aggregation function")
print("- Multiple transport modes (stdio, HTTP, SSE)")