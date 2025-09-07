# Let me create a comprehensive data structure for the recon tools and MCP integration information
import json

# Comprehensive data structure for recon tools and MCP integration
recon_tools_data = {
    "tools": {
        "SUBFINDER": {
            "description": "Fast passive subdomain enumeration tool by ProjectDiscovery",
            "purpose": "Passive subdomain discovery using multiple online sources",
            "github": "github.com/projectdiscovery/subfinder",
            "features": [
                "Fast and powerful resolution and wildcard elimination",
                "Curated passive sources to maximize results",
                "Multiple output formats (JSON, file, stdout)",
                "Optimized for speed and lightweight on resources",
                "STDIN/OUT support enables easy integration"
            ],
            "data_sources": [
                "censys.io", "shodan.io", "virustotal.com", "crt.sh", 
                "hackertarget.com", "threatminer.org", "certspotter.com"
            ],
            "installation": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "basic_usage": "subfinder -d example.com -o output.txt"
        },
        "ASSETFINDER": {
            "description": "Lightweight subdomain enumeration tool",
            "purpose": "Finding subdomains using OSINT sources",
            "github": "github.com/tomnomnom/assetfinder",
            "features": [
                "Integration with OSINT sources",
                "Efficient data collection",
                "Simple and lightweight",
                "Support for HTTP and HTTPS subdomains"
            ],
            "installation": "go install github.com/tomnomnom/assetfinder@latest",
            "basic_usage": "assetfinder example.com"
        },
        "AMASS": {
            "description": "OWASP tool for external asset discovery combining OSINT with active reconnaissance",
            "purpose": "Comprehensive attack surface mapping and subdomain enumeration",
            "github": "github.com/OWASP/Amass",
            "features": [
                "Active and passive reconnaissance techniques",
                "DNS enumeration and network mapping",
                "ASN and CIDR enumeration",
                "Graph database integration",
                "Multiple data sources correlation"
            ],
            "data_sources": [
                "Multiple certificate transparency logs",
                "DNS databases", "Search engines", "Threat intelligence feeds"
            ],
            "installation": "go install -v github.com/OWASP/Amass/v3/...@master",
            "basic_usage": "amass enum -d example.com"
        },
        "BBOT": {
            "description": "OSINT automation tool for hackers",
            "purpose": "Automated OSINT and reconnaissance",
            "github": "github.com/blacklanternsecurity/bbot",
            "features": [
                "Modular architecture",
                "Multiple output formats",
                "Extensive plugin system",
                "Automated reconnaissance workflows"
            ],
            "installation": "python3 -m pip install bbot",
            "basic_usage": "bbot -t example.com"
        },
        "FFUF": {
            "description": "Fast web fuzzer written in Go",
            "purpose": "Web directory and file fuzzing",
            "github": "github.com/ffuf/ffuf",
            "features": [
                "Fast HTTP fuzzing",
                "Multiple wordlist support",
                "Flexible filtering options",
                "JSON output support"
            ],
            "installation": "go install github.com/ffuf/ffuf@latest",
            "basic_usage": "ffuf -w wordlist.txt -u https://example.com/FUZZ"
        },
        "SUBDOG": {
            "description": "Passive subdomain enumeration tool",
            "purpose": "Fast subdomain discovery",
            "features": [
                "Passive reconnaissance",
                "Multiple source integration",
                "Fast enumeration"
            ]
        },
        "SUDOMY": {
            "description": "Subdomain enumeration tool to collect subdomains and analyze domains",
            "purpose": "Advanced automated reconnaissance framework",
            "github": "github.com/screetsec/Sudomy",
            "features": [
                "Active and passive subdomain enumeration",
                "Subdomain availability testing",
                "Port scanning from collected subdomains",
                "Subdomain takeover testing",
                "Screenshot capabilities",
                "Technology identification"
            ],
            "data_sources": [
                "22 third-party sites including censys.io, shodan.io, dnsdumpster.com"
            ],
            "installation": "git clone https://github.com/screetsec/Sudomy.git",
            "basic_usage": "sudomy -d example.com"
        },
        "DNSCAN": {
            "description": "Python wordlist-based DNS subdomain scanner",
            "purpose": "DNS subdomain brute force and zone transfer",
            "github": "github.com/rbsec/dnscan",
            "features": [
                "Zone transfer attempts",
                "TXT and MX record lookup",
                "Recursive subdomain scanning",
                "IPv6 support",
                "Multiple wordlists"
            ],
            "installation": "git clone https://github.com/rbsec/dnscan.git",
            "basic_usage": "python dnscan.py -d example.com"
        },
        "SUBDOMAINATOR": {
            "description": "Fast CLI tool for detecting subdomain takeovers",
            "purpose": "Subdomain takeover detection",
            "github": "github.com/Stratus-Security/Subdominator",
            "features": [
                "97 service fingerprints",
                "Advanced DNS matching (CNAME, A, AAAA)",
                "Recursive DNS queries",
                "Domain registration detection",
                "High-speed performance",
                "Validation capabilities"
            ],
            "installation": "Download from releases or build from source",
            "basic_usage": "Subdominator -d example.com"
        },
        "ASN_CIDR": {
            "description": "ASN and CIDR enumeration tools",
            "purpose": "IP range and autonomous system discovery",
            "tools": {
                "ASNMAP": {
                    "github": "github.com/projectdiscovery/asnmap",
                    "features": [
                        "ASN to CIDR lookup",
                        "ORG to CIDR lookup", 
                        "DNS to CIDR lookup",
                        "IP to CIDR lookup",
                        "Multiple output formats"
                    ],
                    "installation": "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
                    "basic_usage": "asnmap -org GOOGLE"
                }
            }
        }
    },
    "mcp_framework": {
        "description": "Model Context Protocol - open standard for connecting AI assistants to external tools and data sources",
        "purpose": "Standardize AI-tool integration and enable faster data collection",
        "announcement_date": "November 2024",
        "announced_by": "Anthropic",
        "key_benefits": [
            "Universal interface for AI-tool integration",
            "Eliminates N×M integration problem",
            "Standardized protocol across vendors",
            "Improved operational efficiency",
            "Faster threat response in cybersecurity"
        ],
        "transport_mechanisms": [
            "stdio (Standard Input/Output)",
            "HTTP with Server-Sent Events (SSE)",
            "Streamable HTTP"
        ],
        "components": {
            "MCP_Host": "AI application environment (e.g., Claude Desktop)",
            "MCP_Client": "Translates between LLM and MCP server",
            "MCP_Server": "External service providing tools/data",
            "Transport_Layer": "JSON-RPC 2.0 communication"
        }
    },
    "fastmcp_framework": {
        "description": "High-level Python framework for building MCP servers and clients",
        "purpose": "Simplify MCP server development with minimal boilerplate",
        "github": "github.com/jlowin/fastmcp",
        "key_features": [
            "Decorator-based API (@mcp.tool, @mcp.resource)",
            "Automatic schema generation from type hints",
            "Pydantic integration for validation",
            "Async support",
            "Multiple transport protocols",
            "Built-in client implementation",
            "8x faster than existing tools"
        ],
        "installation": "uv pip install fastmcp",
        "basic_server_example": """
from fastmcp import FastMCP

mcp = FastMCP("Recon Tools Server")

@mcp.tool
def run_subfinder(domain: str) -> str:
    \"\"\"Run subfinder on domain\"\"\"
    import subprocess
    result = subprocess.run(['subfinder', '-d', domain], capture_output=True, text=True)
    return result.stdout

if __name__ == "__main__":
    mcp.run()
"""
    },
    "cybersecurity_mcp_applications": {
        "automated_incident_response": "AI agents retrieve alerts, examine logs, suggest remediation",
        "threat_intelligence_correlation": "Cross-reference internal events with external threat intel",
        "vulnerability_management": "Access scan reports, interpret patch priorities",
        "recon_automation": "Integrate multiple reconnaissance tools through single interface",
        "benefits": [
            "Improved governance and auditability",
            "Tool interoperability across platforms",
            "Faster deployment of security use cases",
            "Resource optimization"
        ]
    },
    "integration_architecture": {
        "recon_tools_mcp_integration": {
            "approach": "Create MCP server that wraps multiple recon tools",
            "tools_integration": [
                "Subfinder for passive subdomain enumeration",
                "Amass for comprehensive reconnaissance", 
                "Assetfinder for lightweight discovery",
                "BBOT for automated OSINT",
                "FFUF for directory fuzzing",
                "Sudomy for advanced analysis",
                "Dnscan for DNS scanning",
                "Subdomainator for takeover detection",
                "ASNMap for IP range discovery"
            ],
            "data_flow": [
                "Input: Target domain/organization",
                "Processing: Parallel tool execution",
                "Aggregation: Combine and deduplicate results",
                "Output: Unified JSON/CSV format",
                "MCP Integration: Expose via FastMCP server"
            ]
        }
    }
}

# Save to JSON for later use
with open('recon_mcp_data.json', 'w') as f:
    json.dump(recon_tools_data, f, indent=2)

print("Comprehensive recon tools and MCP integration data structure created!")
print("\nKey findings:")
print("1. MCP enables standardized AI-tool integration")
print("2. FastMCP provides 8x performance improvement")
print("3. All listed recon tools can be integrated via MCP")
print("4. Cybersecurity use cases include automated recon workflows")
print("5. FastMCP supports decorator-based tool wrapping")