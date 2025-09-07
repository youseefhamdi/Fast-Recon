
# MCP RECON Server - Bug Bounty Reconnaissance Tools Integration
# This server integrates multiple reconnaissance tools with the Model Context Protocol

import subprocess
import json
import asyncio
import tempfile
from pathlib import Path
from typing import List, Dict, Optional
from mcp.server.fastmcp import FastMCP
from mcp.server.models import Tool, Resource
from mcp.server import NotificationOptions, Server
import mcp.server.stdio
import logging

# Initialize the MCP server
mcp = FastMCP("BugBounty-Recon-Tools")

class ReconToolsIntegration:
    """Integration class for various reconnaissance tools"""

    def __init__(self):
        self.tools = {
            'subfinder': {'cmd': 'subfinder', 'type': 'passive'},
            'assetfinder': {'cmd': 'assetfinder', 'type': 'passive'},
            'amass': {'cmd': 'amass', 'type': 'hybrid'},
            'bbot': {'cmd': 'bbot', 'type': 'hybrid'},
            'ffuf': {'cmd': 'ffuf', 'type': 'active'},
            'sudomy': {'cmd': 'sudomy', 'type': 'hybrid'},
            'dnscan': {'cmd': 'dnscan.py', 'type': 'active'},
        }

    async def run_tool(self, tool_name: str, target: str, options: Dict = None) -> Dict:
        """Execute a reconnaissance tool with specified parameters"""
        if tool_name not in self.tools:
            return {"error": f"Tool {tool_name} not found"}

        try:
            cmd_parts = self._build_command(tool_name, target, options)
            result = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=300)

            return {
                "tool": tool_name,
                "target": target,
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr if result.stderr else None,
                "command": ' '.join(cmd_parts)
            }
        except subprocess.TimeoutExpired:
            return {"error": f"Tool {tool_name} timed out after 300 seconds"}
        except Exception as e:
            return {"error": f"Failed to run {tool_name}: {str(e)}"}

    def _build_command(self, tool_name: str, target: str, options: Dict = None) -> List[str]:
        """Build command based on tool type and parameters"""
        options = options or {}

        commands = {
            'subfinder': [
                'subfinder', '-d', target, '-silent', '-json'
            ],
            'assetfinder': [
                'assetfinder', '--subs-only', target
            ],
            'amass': [
                'amass', 'enum', '-d', target, '-json', '/dev/stdout'
            ],
            'bbot': [
                'bbot', '-t', target, '-f', 'subdomain-enum', '--output-format', 'json'
            ],
            'ffuf': [
                'ffuf', '-u', f"http://FUZZ.{target}", '-w', options.get('wordlist', '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt'), '-mc', '200', '-json'
            ],
            'sudomy': [
                'sudomy', '-d', target, '--json'
            ],
            'dnscan': [
                'python3', 'dnscan.py', '-d', target, '-o', '/dev/stdout'
            ]
        }

        base_cmd = commands.get(tool_name, [tool_name, target])

        # Add additional options if provided
        if options:
            if 'threads' in options:
                base_cmd.extend(['-t', str(options['threads'])])
            if 'timeout' in options:
                base_cmd.extend(['--timeout', str(options['timeout'])])
            if 'sources' in options:
                base_cmd.extend(['-s', options['sources']])

        return base_cmd

# Initialize the tool integration
recon = ReconToolsIntegration()

@mcp.tool()
def subdomain_enum_subfinder(domain: str, sources: Optional[str] = None) -> dict:
    """
    Enumerate subdomains using Subfinder - Fast passive subdomain enumeration tool.

    Args:
        domain: Target domain to enumerate (e.g., 'example.com')
        sources: Specific sources to use (optional, comma-separated)

    Returns:
        Dictionary containing enumerated subdomains and metadata
    """
    options = {'sources': sources} if sources else {}
    result = asyncio.run(recon.run_tool('subfinder', domain, options))
    return result

@mcp.tool()
def subdomain_enum_assetfinder(domain: str) -> dict:
    """
    Find related domains and subdomains using Assetfinder.

    Args:
        domain: Target domain to enumerate (e.g., 'example.com')

    Returns:
        Dictionary containing discovered assets
    """
    result = asyncio.run(recon.run_tool('assetfinder', domain))
    return result

@mcp.tool()
def comprehensive_enum_amass(domain: str, passive: bool = False) -> dict:
    """
    Perform comprehensive subdomain enumeration using OWASP Amass.

    Args:
        domain: Target domain to enumerate (e.g., 'example.com')
        passive: Use passive enumeration only (default: False)

    Returns:
        Dictionary containing comprehensive enumeration results
    """
    options = {'passive': passive}
    result = asyncio.run(recon.run_tool('amass', domain, options))
    return result

@mcp.tool()
def automated_recon_bbot(target: str, modules: Optional[str] = None) -> dict:
    """
    Run automated reconnaissance using BBOT framework.

    Args:
        target: Target domain or IP to scan
        modules: Specific modules to run (optional)

    Returns:
        Dictionary containing automated recon results
    """
    options = {'modules': modules} if modules else {}
    result = asyncio.run(recon.run_tool('bbot', target, options))
    return result

@mcp.tool()
def fuzzing_ffuf(domain: str, wordlist: Optional[str] = None, threads: int = 10) -> dict:
    """
    Perform directory/subdomain fuzzing using FFUF.

    Args:
        domain: Target domain for fuzzing
        wordlist: Path to wordlist file (optional)
        threads: Number of threads to use (default: 10)

    Returns:
        Dictionary containing fuzzing results
    """
    options = {
        'wordlist': wordlist,
        'threads': threads
    }
    result = asyncio.run(recon.run_tool('ffuf', domain, options))
    return result

@mcp.tool()
def comprehensive_sudomy(domain: str, passive_only: bool = False) -> dict:
    """
    Comprehensive subdomain analysis using Sudomy framework.

    Args:
        domain: Target domain to analyze
        passive_only: Use passive enumeration only (default: False)

    Returns:
        Dictionary containing comprehensive analysis results
    """
    options = {'passive': passive_only}
    result = asyncio.run(recon.run_tool('sudomy', domain, options))
    return result

@mcp.tool()
def dns_bruteforce_dnscan(domain: str, wordlist: Optional[str] = None, threads: int = 8) -> dict:
    """
    Perform DNS bruteforce scanning using dnscan.

    Args:
        domain: Target domain for DNS scanning
        wordlist: Path to wordlist file (optional)
        threads: Number of threads to use (default: 8)

    Returns:
        Dictionary containing DNS scan results
    """
    options = {
        'wordlist': wordlist,
        'threads': threads
    }
    result = asyncio.run(recon.run_tool('dnscan', domain, options))
    return result

@mcp.tool()
def asn_cidr_enum(target: str, enum_type: str = 'asn') -> dict:
    """
    Enumerate ASN and CIDR ranges for target organization.

    Args:
        target: Target domain or organization
        enum_type: Type of enumeration ('asn', 'cidr', or 'both')

    Returns:
        Dictionary containing ASN/CIDR enumeration results
    """
    try:
        results = {}

        if enum_type in ['asn', 'both']:
            # ASN enumeration using asnmap or whois
            asn_cmd = ['asnmap', '-d', target, '-json']
            asn_result = subprocess.run(asn_cmd, capture_output=True, text=True, timeout=60)
            results['asn'] = {
                'success': asn_result.returncode == 0,
                'output': asn_result.stdout,
                'error': asn_result.stderr
            }

        if enum_type in ['cidr', 'both']:
            # CIDR enumeration
            cidr_cmd = ['asnmap', '-a', target, '-cidr', '-json']
            cidr_result = subprocess.run(cidr_cmd, capture_output=True, text=True, timeout=60)
            results['cidr'] = {
                'success': cidr_result.returncode == 0,
                'output': cidr_result.stdout,
                'error': cidr_result.stderr
            }

        return results

    except Exception as e:
        return {"error": f"Failed to enumerate ASN/CIDR: {str(e)}"}

@mcp.tool()
def multi_tool_recon(domain: str, tools: Optional[List[str]] = None, passive_only: bool = False) -> dict:
    """
    Run multiple reconnaissance tools on a target domain.

    Args:
        domain: Target domain to scan
        tools: List of tools to run (optional, runs all if not specified)
        passive_only: Only run passive enumeration tools

    Returns:
        Dictionary containing results from all specified tools
    """
    if tools is None:
        tools = ['subfinder', 'assetfinder', 'amass']
        if not passive_only:
            tools.extend(['ffuf', 'dnscan'])

    results = {}

    for tool in tools:
        if passive_only and recon.tools.get(tool, {}).get('type') == 'active':
            continue

        try:
            result = asyncio.run(recon.run_tool(tool, domain))
            results[tool] = result
        except Exception as e:
            results[tool] = {"error": f"Failed to run {tool}: {str(e)}"}

    return results

# Resources
@mcp.resource("recon://tools/list")
def list_available_tools() -> str:
    """List all available reconnaissance tools and their capabilities."""
    tool_info = []
    for name, info in recon.tools.items():
        tool_info.append(f"- {name}: {info['type']} enumeration tool")

    return "Available Reconnaissance Tools:\n" + "\n".join(tool_info)

@mcp.resource("recon://wordlists/common")
def get_common_wordlists() -> str:
    """Get information about commonly used wordlists for reconnaissance."""
    wordlists = [
        "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt"
    ]

    return "Common Wordlists for Reconnaissance:\n" + "\n".join(f"- {wl}" for wl in wordlists)

# Server configuration and startup
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)

    # Run the MCP server
    mcp.run()
