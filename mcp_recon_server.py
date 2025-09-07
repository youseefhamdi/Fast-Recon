# MCP RECON Server - Bug Bounty Reconnaissance Tools Integration
# Updated for MCP >= 1.13.1 (no decorators)

import subprocess
import asyncio
import logging
from typing import List, Dict, Optional

from mcp.server import Server
import mcp.server.stdio

# Initialize the MCP server
server = Server("BugBounty-Recon-Tools")

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
        options = options or {}
        commands = {
            'subfinder': ["subfinder", "-d", target, "-silent", "-json"],
            'assetfinder': ["assetfinder", "--subs-only", target],
            'amass': ["amass", "enum", "-d", target, "-json", "/dev/stdout"],
            'bbot': ["bbot", "-t", target, "-f", "subdomain-enum", "--output-format", "json"],
            'ffuf': [
                "ffuf", "-u", f"http://FUZZ.{target}",
                "-w", options.get("wordlist", "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"),
                "-mc", "200", "-json"
            ],
            'sudomy': ["sudomy", "-d", target, "--json"],
            'dnscan': ["python3", "dnscan.py", "-d", target, "-o", "/dev/stdout"],
        }
        return commands.get(tool_name, [tool_name, target])

# Tool integration object
recon = ReconToolsIntegration()

# ----------------------------
# Tool functions
# ----------------------------

async def subdomain_enum_subfinder(domain: str, sources: Optional[str] = None) -> dict:
    options = {"sources": sources} if sources else {}
    return await recon.run_tool("subfinder", domain, options)

async def subdomain_enum_assetfinder(domain: str) -> dict:
    return await recon.run_tool("assetfinder", domain)

async def comprehensive_enum_amass(domain: str, passive: bool = False) -> dict:
    return await recon.run_tool("amass", domain, {"passive": passive})

async def automated_recon_bbot(target: str, modules: Optional[str] = None) -> dict:
    return await recon.run_tool("bbot", target, {"modules": modules} if modules else {})

async def fuzzing_ffuf(domain: str, wordlist: Optional[str] = None, threads: int = 10) -> dict:
    return await recon.run_tool("ffuf", domain, {"wordlist": wordlist, "threads": threads})

async def comprehensive_sudomy(domain: str, passive_only: bool = False) -> dict:
    return await recon.run_tool("sudomy", domain, {"passive": passive_only})

async def dns_bruteforce_dnscan(domain: str, wordlist: Optional[str] = None, threads: int = 8) -> dict:
    return await recon.run_tool("dnscan", domain, {"wordlist": wordlist, "threads": threads})

async def asn_cidr_enum(target: str, enum_type: str = "asn") -> dict:
    results = {}
    try:
        if enum_type in ["asn", "both"]:
            asn_cmd = ["asnmap", "-d", target, "-json"]
            asn_result = subprocess.run(asn_cmd, capture_output=True, text=True, timeout=60)
            results["asn"] = {"success": asn_result.returncode == 0, "output": asn_result.stdout, "error": asn_result.stderr}
        if enum_type in ["cidr", "both"]:
            cidr_cmd = ["asnmap", "-a", target, "-cidr", "-json"]
            cidr_result = subprocess.run(cidr_cmd, capture_output=True, text=True, timeout=60)
            results["cidr"] = {"success": cidr_result.returncode == 0, "output": cidr_result.stdout, "error": cidr_result.stderr}
        return results
    except Exception as e:
        return {"error": str(e)}

async def multi_tool_recon(domain: str, tools: Optional[List[str]] = None, passive_only: bool = False) -> dict:
    if tools is None:
        tools = ["subfinder", "assetfinder", "amass"]
        if not passive_only:
            tools.extend(["ffuf", "dnscan"])
    results = {}
    for tool in tools:
        if passive_only and recon.tools.get(tool, {}).get("type") == "active":
            continue
        try:
            results[tool] = await recon.run_tool(tool, domain)
        except Exception as e:
            results[tool] = {"error": f"Failed to run {tool}: {str(e)}"}
    return results

# ----------------------------
# Resources
# ----------------------------

async def list_available_tools() -> str:
    return "Available Reconnaissance Tools:\n" + "\n".join(
        f"- {name}: {info['type']} enumeration tool" for name, info in recon.tools.items()
    )

async def get_common_wordlists() -> str:
    wordlists = [
        "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt",
    ]
    return "Common Wordlists for Reconnaissance:\n" + "\n".join(f"- {wl}" for wl in wordlists)

# ----------------------------
# Register tools/resources
# ----------------------------

server.register_tool(subdomain_enum_subfinder)
server.register_tool(subdomain_enum_assetfinder)
server.register_tool(comprehensive_enum_amass)
server.register_tool(automated_recon_bbot)
server.register_tool(fuzzing_ffuf)
server.register_tool(comprehensive_sudomy)
server.register_tool(dns_bruteforce_dnscan)
server.register_tool(asn_cidr_enum)
server.register_tool(multi_tool_recon)

server.register_resource("recon://tools/list", list_available_tools)
server.register_resource("recon://wordlists/common", get_common_wordlists)

# ----------------------------
# Server startup
# ----------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mcp.server.stdio.run_server(server)
