# Bug Bounty Recon Tools MCP Server Usage Examples

## Starting the MCP Server

### Stdio Mode (for local AI clients)
```bash
python3 recon-mcp-server.py
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
      "args": ["/path/to/recon-mcp-server.py"]
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
    async with Client("python3 recon-mcp-server.py") as client:
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

## Configuration Files

### API Keys Configuration
Many tools require API keys for enhanced functionality. Create configuration files:

#### Subfinder Configuration (~/.config/subfinder/provider-config.yaml)
```yaml
shodan:
  - your_shodan_api_key
virustotal:
  - your_virustotal_api_key
censys:
  - your_censys_api_id:your_censys_secret
github:
  - your_github_token
```

#### Amass Configuration (~/.config/amass/config.ini)
```ini
[data_sources.Shodan]
ttl = 4320
api_key = your_shodan_api_key

[data_sources.VirusTotal]
ttl = 10080
api_key = your_virustotal_api_key
```

### MCP Client Configuration

#### Claude Desktop (claude_desktop_config.json)
```json
{
  "mcpServers": {
    "recon-tools": {
      "command": "python3",
      "args": ["/absolute/path/to/recon-mcp-server.py"],
      "env": {
        "PATH": "/usr/local/bin:/usr/bin:/bin"
      }
    }
  }
}
```

#### VS Code Settings (settings.json)
```json
{
  "mcp.servers": {
    "recon-tools": {
      "command": "python3",
      "args": ["/path/to/recon-mcp-server.py"],
      "description": "Bug bounty reconnaissance tools"
    }
  }
}
```

## Workflow Examples

### Basic Bug Bounty Workflow
1. Start with passive reconnaissance:
   ```
   run_complete_recon("target.com", include_aggressive=False)
   ```

2. Analyze ASN and IP ranges:
   ```
   run_asnmap("TARGET_ORG", "org")
   ```

3. Check for subdomain takeovers:
   ```
   run_subdomainator("target.com", validate=True)
   ```

4. Fuzz discovered subdomains:
   ```
   run_ffuf("https://subdomain.target.com/FUZZ", "wordlist.txt")
   ```

### Advanced Reconnaissance Workflow
```python
async def advanced_recon(domain):
    # Step 1: Passive enumeration
    passive_results = await run_complete_recon(domain, False)
    
    # Step 2: Extract subdomains from results
    subdomains = extract_subdomains_from_results(passive_results)
    
    # Step 3: Check each subdomain for takeovers
    for subdomain in subdomains:
        takeover_result = await run_subdomainator(subdomain, True)
        if "vulnerable" in takeover_result.lower():
            print(f"Potential takeover: {subdomain}")
    
    # Step 4: ASN/CIDR discovery
    asn_results = await run_asnmap(domain, "domain")
    
    return {
        "passive": passive_results,
        "takeovers": takeover_results,
        "asn": asn_results
    }
```

## Security Considerations

### Input Validation
The MCP server includes basic input validation to prevent command injection:
- Domain names are validated against regex patterns
- File paths are sanitized
- Command arguments are properly escaped

### Rate Limiting
Implement rate limiting for external API calls:
```python
import time
from functools import wraps

def rate_limit(calls_per_minute=60):
    def decorator(func):
        last_called = [0.0]
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            left_to_wait = 60.0 / calls_per_minute - elapsed
            if left_to_wait > 0:
                time.sleep(left_to_wait)
            ret = func(*args, **kwargs)
            last_called[0] = time.time()
            return ret
        return wrapper
    return decorator
```

### Network Security
- Use VPN or proxy for reconnaissance activities
- Implement timeout controls to prevent hanging processes
- Log all reconnaissance activities for audit purposes

## Troubleshooting

### Common Issues

1. **Tools not found in PATH**
   ```bash
   export PATH=$PATH:$(go env GOPATH)/bin
   ```

2. **Permission errors**
   ```bash
   chmod +x install-recon-tools.sh
   sudo chmod +x /usr/local/bin/*
   ```

3. **API rate limiting**
   - Configure API keys properly
   - Implement delays between requests
   - Use multiple API keys for rotation

4. **Memory issues with large scans**
   - Reduce timeout values
   - Process results in batches
   - Use streaming output when available

### Logging and Debugging
Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Check tool status:
```bash
python3 -c "from recon_mcp_server import get_recon_tools_status; print(get_recon_tools_status())"
```