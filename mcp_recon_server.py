#!/usr/bin/env python3
"""
MCP RECON Server - Bug Bounty Reconnaissance Tools Integration
Uses the official MCP Python SDK with FastMCP for easy tool integration
"""

import asyncio
import json
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from mcp.server.fastmcp import FastMCP
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("BugBounty-Recon-Tools")

class ReconToolRunner:
    """Utility class to run reconnaissance tools safely"""

    @staticmethod
    async def run_command(command: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Run a command asynchronously with timeout"""
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024*1024  # 1MB limit
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )

            return {
                "success": process.returncode == 0,
                "returncode": process.returncode,
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore'),
                "command": ' '.join(command)
            }

        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": f"Command timed out after {timeout} seconds",
                "command": ' '.join(command)
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": ' '.join(command)
            }

# Initialize tool runner
runner = ReconToolRunner()

# === PASSIVE RECONNAISSANCE TOOLS ===

@mcp.tool()
def subfinder_enum(domain: str, sources: Optional[str] = None, threads: int = 10) -> dict:
    """
    Enumerate subdomains using Subfinder - Fast passive subdomain enumeration.

    Args:
        domain: Target domain to enumerate (e.g., 'example.com')
        sources: Comma-separated list of sources to use (optional)
        threads: Number of concurrent threads (default: 10)

    Returns:
        Dictionary containing enumerated subdomains and metadata
    """
    command = ["subfinder", "-d", domain, "-silent", "-t", str(threads)]

    if sources:
        command.extend(["-sources", sources])

    result = asyncio.run(runner.run_command(command))

    if result.get("success"):
        # Parse subdomains from output
        subdomains = [line.strip() for line in result["stdout"].split('\n') if line.strip()]
        result["subdomains"] = subdomains
        result["count"] = len(subdomains)

    return result

@mcp.tool()
def assetfinder_enum(domain: str, subs_only: bool = True) -> dict:
    """
    Find related domains and subdomains using Assetfinder.

    Args:
        domain: Target domain to enumerate
        subs_only: Only return subdomains (default: True)

    Returns:
        Dictionary containing discovered assets
    """
    command = ["assetfinder"]

    if subs_only:
        command.append("--subs-only")

    command.append(domain)

    result = asyncio.run(runner.run_command(command))

    if result.get("success"):
        assets = [line.strip() for line in result["stdout"].split('\n') if line.strip()]
        result["assets"] = assets
        result["count"] = len(assets)

    return result

@mcp.tool()
def subdomainator_enum(domain: str, sources: str = "all", threads: int = 10) -> dict:
    """
    Comprehensive subdomain enumeration using Subdomainator.

    Args:
        domain: Target domain to analyze
        sources: Sources to use ('all', 'passive', or specific sources)
        threads: Number of threads (default: 10)

    Returns:
        Dictionary containing enumeration results
    """
    # Check if subdomainator is available as a Python module or script
    command = ["python3", "-c", f"""
import sys
sys.path.append('/opt/subdomainator')
from subdomainator import main
main(['-d', '{domain}', '-t', '{threads}', '--sources', '{sources}'])
"""]

    # Fallback to direct execution if available
    try:
        # First try as installed command
        test_command = ["subdomainator", "--help"]
        test_result = asyncio.run(runner.run_command(test_command, timeout=5))
        if test_result.get("success"):
            command = ["subdomainator", "-d", domain, "-t", str(threads), "--sources", sources]
    except:
        pass

    result = asyncio.run(runner.run_command(command))

    if result.get("success"):
        # Parse results from output
        lines = [line.strip() for line in result["stdout"].split('\n') if line.strip()]
        subdomains = [line for line in lines if '.' in line and not line.startswith('[')]
        result["subdomains"] = subdomains
        result["count"] = len(subdomains)

    return result

# === ACTIVE RECONNAISSANCE TOOLS ===

@mcp.tool()
def ffuf_enum(domain: str, wordlist: str = "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt", threads: int = 10) -> dict:
    """
    Perform subdomain fuzzing using FFUF.

    Args:
        domain: Target domain for fuzzing
        wordlist: Path to wordlist file
        threads: Number of threads (default: 10)

    Returns:
        Dictionary containing fuzzing results
    """
    # Check if wordlist exists, use fallback if not
    if not os.path.exists(wordlist):
        # Create a small default wordlist
        default_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev', 'staging', 'beta']
        default_wordlist.write('\n'.join(common_subs))
        default_wordlist.close()
        wordlist = default_wordlist.name

    command = [
        "ffuf", 
        "-u", f"http://FUZZ.{domain}",
        "-w", wordlist,
        "-mc", "200,204,301,302,307,401,403",
        "-t", str(threads),
        "-sf"  # Silent mode, only show found results
    ]

    result = asyncio.run(runner.run_command(command))

    # Clean up temp file if created
    if wordlist.startswith('/tmp'):
        try:
            os.unlink(wordlist)
        except:
            pass

    if result.get("success"):
        # Parse FFUF output for found subdomains
        found_hosts = []
        for line in result["stdout"].split('\n'):
            if 'FUZZ' not in line and domain in line and ('200' in line or '301' in line):
                parts = line.split()
                if parts:
                    found_hosts.append(parts[0] if '.' in parts[0] else f"{parts[0]}.{domain}")

        result["found_hosts"] = found_hosts
        result["count"] = len(found_hosts)

    return result

@mcp.tool()
def dnscan_enum(domain: str, wordlist: Optional[str] = None, threads: int = 8) -> dict:
    """
    Perform DNS brute force scanning using DNScan.

    Args:
        domain: Target domain for DNS scanning
        wordlist: Path to wordlist file (optional)
        threads: Number of threads (default: 8)

    Returns:
        Dictionary containing DNS scan results
    """
    # Try different ways to run dnscan
    possible_commands = [
        ["dnscan.py", "-d", domain, "-t", str(threads)],
        ["python3", "/opt/dnscan/dnscan.py", "-d", domain, "-t", str(threads)],
        ["python3", "/usr/local/bin/dnscan.py", "-d", domain, "-t", str(threads)]
    ]

    if wordlist and os.path.exists(wordlist):
        for cmd in possible_commands:
            cmd.extend(["-w", wordlist])

    result = {"success": False, "error": "DNScan not found"}

    # Try each possible command
    for command in possible_commands:
        try:
            test_result = asyncio.run(runner.run_command(command[:2] + ["--help"], timeout=5))
            if test_result.get("success") or "usage" in test_result.get("stdout", "").lower():
                result = asyncio.run(runner.run_command(command))
                break
        except:
            continue

    if result.get("success"):
        # Parse dnscan output
        subdomains = []
        for line in result["stdout"].split('\n'):
            line = line.strip()
            if line and '.' in line and domain in line:
                # Extract subdomain from various output formats
                if ' - ' in line:
                    subdomain = line.split(' - ')[0].strip()
                elif '\t' in line:
                    subdomain = line.split('\t')[0].strip()
                else:
                    subdomain = line

                if subdomain.endswith(f'.{domain}') or subdomain == domain:
                    subdomains.append(subdomain)

        result["subdomains"] = list(set(subdomains))  # Remove duplicates
        result["count"] = len(result["subdomains"])

    return result

# === HYBRID RECONNAISSANCE TOOLS ===

@mcp.tool()
def amass_enum(domain: str, passive: bool = False, timeout_minutes: int = 10) -> dict:
    """
    Comprehensive subdomain enumeration using OWASP Amass.

    Args:
        domain: Target domain to enumerate
        passive: Use passive enumeration only (default: False)
        timeout_minutes: Timeout in minutes (default: 10)

    Returns:
        Dictionary containing comprehensive enumeration results
    """
    command = ["amass", "enum", "-d", domain, "-nocolor"]

    if passive:
        command.append("-passive")

    result = asyncio.run(runner.run_command(command, timeout=timeout_minutes*60))

    if result.get("success"):
        # Parse amass output
        subdomains = []
        for line in result["stdout"].split('\n'):
            line = line.strip()
            if line and domain in line and not line.startswith('['):
                # Clean up the line to extract just the subdomain
                clean_line = line.split()[0] if line.split() else line
                if '.' in clean_line and (clean_line.endswith(f'.{domain}') or clean_line == domain):
                    subdomains.append(clean_line)

        result["subdomains"] = list(set(subdomains))
        result["count"] = len(result["subdomains"])

    return result

@mcp.tool()
def bbot_recon(target: str, modules: Optional[str] = None, flags: str = "subdomain-enum") -> dict:
    """
    Automated reconnaissance using BBOT framework.

    Args:
        target: Target domain or IP to scan
        modules: Specific modules to run (optional)
        flags: BBOT flags to use (default: subdomain-enum)

    Returns:
        Dictionary containing automated recon results
    """
    command = ["bbot", "-t", target, "-f", flags]

    if modules:
        command.extend(["-m", modules])

    # Add output format
    command.extend(["--output-format", "json"])

    result = asyncio.run(runner.run_command(command, timeout=600))  # 10 minute timeout

    if result.get("success"):
        # Parse BBOT JSON output
        try:
            results = []
            for line in result["stdout"].split('\n'):
                if line.strip() and line.startswith('{'):
                    try:
                        data = json.loads(line)
                        if 'data' in data and 'type' in data:
                            results.append(data)
                    except:
                        continue

            result["bbot_results"] = results
            result["count"] = len(results)
        except Exception as e:
            result["parse_error"] = str(e)

    return result

@mcp.tool()
def sudomy_recon(domain: str, passive_only: bool = False, modules: str = "all") -> dict:
    """
    Comprehensive subdomain analysis using Sudomy framework.

    Args:
        domain: Target domain to analyze
        passive_only: Use passive enumeration only (default: False)
        modules: Modules to run (default: all)

    Returns:
        Dictionary containing comprehensive analysis results
    """
    # Try different ways to run sudomy
    possible_commands = [
        ["sudomy", "-d", domain],
        ["bash", "/opt/Sudomy/sudomy", "-d", domain],
        ["./sudomy", "-d", domain]
    ]

    # Add flags based on options
    for command in possible_commands:
        if passive_only:
            command.append("--passive")

        # Try to add output format if supported
        command.extend(["--output", "json"])

    result = {"success": False, "error": "Sudomy not found"}

    # Try each possible command
    for command in possible_commands:
        try:
            test_result = asyncio.run(runner.run_command(command[:2] + ["--help"], timeout=5))
            if test_result.get("success") or "sudomy" in test_result.get("stdout", "").lower():
                result = asyncio.run(runner.run_command(command, timeout=900))  # 15 minute timeout
                break
        except:
            continue

    if result.get("success"):
        # Parse sudomy output for subdomains
        subdomains = []
        for line in result["stdout"].split('\n'):
            line = line.strip()
            if line and domain in line and not line.startswith('[') and not line.startswith('#'):
                if line.endswith(f'.{domain}') or line == domain:
                    subdomains.append(line)

        result["subdomains"] = list(set(subdomains))
        result["count"] = len(result["subdomains"])

    return result

# === ASN & CIDR ENUMERATION ===

@mcp.tool()
def asnmap_enum(target: str, enum_type: str = "asn") -> dict:
    """
    Enumerate ASN and CIDR ranges using ASNmap.

    Args:
        target: Target domain or organization
        enum_type: Type of enumeration ('asn', 'cidr', or 'both')

    Returns:
        Dictionary containing ASN/CIDR enumeration results
    """
    results = {}

    if enum_type in ['asn', 'both']:
        # ASN enumeration
        asn_command = ["asnmap", "-d", target]
        asn_result = asyncio.run(runner.run_command(asn_command))
        results['asn'] = asn_result

    if enum_type in ['cidr', 'both']:
        # CIDR enumeration
        cidr_command = ["asnmap", "-d", target, "-cidr"]
        cidr_result = asyncio.run(runner.run_command(cidr_command))
        results['cidr'] = cidr_result

    return results

# === MULTI-TOOL WORKFLOWS ===

@mcp.tool()
def multi_tool_recon(domain: str, tools: Optional[str] = "passive", timeout_per_tool: int = 300) -> dict:
    """
    Run multiple reconnaissance tools on a target domain.

    Args:
        domain: Target domain to scan
        tools: Tools to run ('passive', 'active', 'all', or comma-separated list)
        timeout_per_tool: Timeout per tool in seconds

    Returns:
        Dictionary containing results from all specified tools
    """
    results = {"domain": domain, "tools_run": [], "results": {}}

    # Define tool sets
    passive_tools = ["subfinder_enum", "assetfinder_enum"]
    active_tools = ["ffuf_enum", "dnscan_enum"]
    hybrid_tools = ["amass_enum", "bbot_recon"]

    # Select tools based on input
    selected_tools = []
    if tools == "passive":
        selected_tools = passive_tools
    elif tools == "active":
        selected_tools = active_tools
    elif tools == "hybrid":
        selected_tools = hybrid_tools
    elif tools == "all":
        selected_tools = passive_tools + active_tools + hybrid_tools
    else:
        # Custom tool list
        selected_tools = [t.strip() for t in tools.split(',')]

    # Run each tool
    for tool_name in selected_tools:
        try:
            if tool_name == "subfinder_enum":
                result = subfinder_enum(domain)
            elif tool_name == "assetfinder_enum":
                result = assetfinder_enum(domain)
            elif tool_name == "ffuf_enum":
                result = ffuf_enum(domain)
            elif tool_name == "dnscan_enum":
                result = dnscan_enum(domain)
            elif tool_name == "amass_enum":
                result = amass_enum(domain, passive=True)
            elif tool_name == "bbot_recon":
                result = bbot_recon(domain)
            else:
                result = {"success": False, "error": f"Unknown tool: {tool_name}"}

            results["results"][tool_name] = result
            results["tools_run"].append(tool_name)

        except Exception as e:
            results["results"][tool_name] = {
                "success": False,
                "error": f"Tool execution failed: {str(e)}"
            }

    # Aggregate findings
    all_subdomains = set()
    successful_tools = 0

    for tool_name, result in results["results"].items():
        if result.get("success"):
            successful_tools += 1
            # Extract subdomains from various result formats
            if "subdomains" in result:
                all_subdomains.update(result["subdomains"])
            elif "assets" in result:
                all_subdomains.update(result["assets"])
            elif "found_hosts" in result:
                all_subdomains.update(result["found_hosts"])

    results["summary"] = {
        "total_tools": len(selected_tools),
        "successful_tools": successful_tools,
        "unique_subdomains": sorted(list(all_subdomains)),
        "subdomain_count": len(all_subdomains)
    }

    return results

# === UTILITY FUNCTIONS ===

@mcp.tool()
def check_tool_availability() -> dict:
    """
    Check which reconnaissance tools are available on the system.

    Returns:
        Dictionary showing availability of each tool
    """
    tools_to_check = [
        "subfinder", "assetfinder", "amass", "bbot", 
        "ffuf", "dnscan.py", "sudomy", "asnmap"
    ]

    availability = {}

    for tool in tools_to_check:
        try:
            result = asyncio.run(runner.run_command([tool, "--help"], timeout=5))
            availability[tool] = {
                "available": result.get("success", False) or "usage" in result.get("stdout", "").lower(),
                "version_check": result.get("stdout", "")[:200] if result.get("stdout") else ""
            }
        except Exception as e:
            availability[tool] = {
                "available": False,
                "error": str(e)
            }

    return availability

# === RESOURCES ===

@mcp.resource("recon://tools/list")
def list_available_tools() -> str:
    """List all available reconnaissance tools and their capabilities."""
    tools_info = {
        "passive_tools": {
            "subfinder": "Fast passive subdomain enumeration using 25+ sources",
            "assetfinder": "Find related domains and subdomains",
            "subdomainator": "Advanced passive enumeration with 50+ sources"
        },
        "active_tools": {
            "ffuf": "High-speed web fuzzer for directory/subdomain discovery",
            "dnscan": "DNS brute force scanner"
        },
        "hybrid_tools": {
            "amass": "OWASP comprehensive attack surface mapping",
            "bbot": "Automated reconnaissance framework",
            "sudomy": "Comprehensive analysis framework"
        },
        "utility_tools": {
            "asnmap": "ASN and CIDR enumeration",
            "multi_tool_recon": "Run multiple tools in sequence"
        }
    }

    return json.dumps(tools_info, indent=2)

@mcp.resource("recon://wordlists/common")
def get_common_wordlists() -> str:
    """Get information about commonly used wordlists for reconnaissance."""
    wordlists = [
        "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt", 
        "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt",
        "/opt/wordlists/subdomains.txt"
    ]

    available_wordlists = []
    for wl in wordlists:
        if os.path.exists(wl):
            size = os.path.getsize(wl)
            available_wordlists.append(f"{wl} ({size} bytes)")
        else:
            available_wordlists.append(f"{wl} (not found)")

    return "\n".join(available_wordlists)

# Main execution
if __name__ == "__main__":
    print("Starting BugBounty MCP Recon Server...")
    print("Available tools: subfinder, assetfinder, amass, bbot, ffuf, dnscan, sudomy, asnmap")
    print("Use check_tool_availability() to verify which tools are installed.")
    mcp.run()
