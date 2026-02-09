"""
CackalackyCon 2026 — Level 2: The Recon Agent
==============================================

A multi-step reconnaissance agent that analyzes pre-captured security data.
No live scanning — all data is in files. Your agent chains tool outputs
together to build a complete threat assessment.

Tools:
  1. read_file      — read any challenge file
  2. search_web     — OSINT lookups (internet permitting)
  3. parse_nmap     — parse pre-captured nmap XML scan results
  4. analyze_headers — check HTTP headers for security misconfigurations
  5. check_cve      — look up CVEs from a local vulnerability database

Run with:
    uv run python level2/agent.py
"""

import os
import json
import xml.etree.ElementTree as ET
from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.prebuilt import create_react_agent


# =============================================================
# CONFIG
# =============================================================

llm = ChatOllama(model="llama3.1:8b", temperature=0)
CHALLENGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenges")


# =============================================================
# TOOLS
# =============================================================


@tool
def read_file(file_path: str) -> str:
    """Read any challenge file. Use this for briefings, DNS records,
    robots.txt, SSL info, or any text-based evidence.

    Input: file path relative to the challenges/ directory.
    Examples: 'briefing.txt', 'recon/dns_records.txt', 'recon/ssl_info.txt'
    """
    try:
        safe_path = os.path.normpath(os.path.join(CHALLENGES_DIR, file_path))
        if not safe_path.startswith(os.path.normpath(CHALLENGES_DIR)):
            return "Access denied."
        if not os.path.exists(safe_path):
            available = []
            for root, dirs, files in os.walk(CHALLENGES_DIR):
                for f in files:
                    available.append(os.path.relpath(os.path.join(root, f), CHALLENGES_DIR))
            return f"File not found: {file_path}\nAvailable:\n" + "\n".join(
                f"  - {f}" for f in available
            )
        with open(safe_path, "r") as f:
            return f.read()[:8000]
    except Exception as e:
        return f"Error: {str(e)}"


@tool
def search_web(query: str) -> str:
    """Search the web using DuckDuckGo for OSINT or CVE research.
    Input: a search query string."""
    try:
        from duckduckgo_search import DDGS

        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=3))
            if not results:
                return "No results found."
            return "\n\n".join(
                f"Title: {r['title']}\nURL: {r['href']}\nSnippet: {r['body']}" for r in results
            )
    except Exception as e:
        return f"Search failed: {str(e)}"


@tool
def parse_nmap(file_path: str) -> str:
    """Parse a pre-captured nmap scan XML file and return structured results.
    Shows open ports, services, versions, and OS detection.

    Input: path to an nmap XML file (e.g., 'recon/scan_results.xml')
    """
    try:
        safe_path = os.path.normpath(os.path.join(CHALLENGES_DIR, file_path))
        if not safe_path.startswith(os.path.normpath(CHALLENGES_DIR)):
            return "Access denied."

        tree = ET.parse(safe_path)
        root = tree.getroot()
        results = []

        for host in root.findall(".//host"):
            addr = host.find("address")
            ip = addr.get("addr", "unknown") if addr is not None else "unknown"
            host_info = {"ip": ip, "ports": [], "os": []}

            for port in host.findall(".//port"):
                state = port.find("state")
                service = port.find("service")
                port_info = {
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": state.get("state") if state is not None else "unknown",
                    "service": service.get("name", "unknown") if service is not None else "unknown",
                    "version": service.get("version", "") if service is not None else "",
                    "product": service.get("product", "") if service is not None else "",
                }
                host_info["ports"].append(port_info)

            for osmatch in host.findall(".//osmatch"):
                host_info["os"].append(
                    {"name": osmatch.get("name"), "accuracy": osmatch.get("accuracy")}
                )

            results.append(host_info)

        return json.dumps(results, indent=2)
    except Exception as e:
        return f"Error parsing nmap XML: {str(e)}"


@tool
def analyze_headers(file_path: str) -> str:
    """Analyze pre-captured HTTP response headers for security misconfigurations.
    Checks for missing security headers, server info leakage, and common issues.

    Input: path to a headers file (e.g., 'recon/http_headers.txt')
    """
    try:
        safe_path = os.path.normpath(os.path.join(CHALLENGES_DIR, file_path))
        if not safe_path.startswith(os.path.normpath(CHALLENGES_DIR)):
            return "Access denied."

        with open(safe_path, "r") as f:
            raw = f.read()

        headers = {}
        for line in raw.strip().split("\n"):
            if ":" in line and not line.startswith("HTTP"):
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()

        findings = []
        security_checks = {
            "strict-transport-security": "HSTS not set — vulnerable to SSL stripping attacks",
            "x-content-type-options": "Missing — browser MIME sniffing possible",
            "x-frame-options": "Missing — clickjacking attacks possible",
            "content-security-policy": "CSP missing — increased XSS risk",
            "x-xss-protection": "XSS protection header missing",
            "referrer-policy": "Referrer-Policy missing — may leak sensitive URLs",
        }

        for header, warning in security_checks.items():
            if header not in headers:
                findings.append(f"MISSING: {warning}")

        if "server" in headers:
            findings.append(f"INFO LEAK: Server header exposes: {headers['server']}")
        if "x-powered-by" in headers:
            findings.append(f"INFO LEAK: X-Powered-By exposes: {headers['x-powered-by']}")
        if "x-debug-token" in headers:
            findings.append(
                f"CRITICAL: Debug token exposed in production: {headers['x-debug-token']}"
            )

        report = f"=== HTTP HEADER SECURITY ANALYSIS ===\n"
        report += f"Headers found: {len(headers)}\n"
        report += f"Issues found: {len(findings)}\n\n"
        for i, finding in enumerate(findings, 1):
            report += f"  {i}. {finding}\n"

        # Also return raw headers for the agent to inspect
        report += f"\n--- Raw Headers ---\n{raw}"
        return report
    except Exception as e:
        return f"Error analyzing headers: {str(e)}"


@tool
def check_cve(search_term: str) -> str:
    """Look up CVE information from a local vulnerability database.
    Search by CVE ID, software name, or version number.

    Input: a CVE ID (e.g., 'CVE-2021-44228') or software name+version (e.g., 'Apache 2.4.49')
    """
    try:
        db_path = os.path.join(CHALLENGES_DIR, "cve_database.json")
        with open(db_path, "r") as f:
            cve_db = json.load(f)

        search_lower = search_term.lower()
        matches = []

        for cve in cve_db:
            searchable = " ".join(
                [
                    cve.get("id", ""),
                    cve.get("software", ""),
                    cve.get("description", ""),
                    cve.get("versions_affected", ""),
                ]
            ).lower()
            if search_lower in searchable:
                matches.append(cve)

        if not matches:
            return f"No CVEs found for '{search_term}'. Try searching by software name or CVE ID."

        output = f"Found {len(matches)} CVE(s) for '{search_term}':\n\n"
        for cve in matches[:5]:
            output += f"  CVE ID: {cve['id']}\n"
            output += f"  Software: {cve['software']}\n"
            output += f"  CVSS Score: {cve['cvss']}\n"
            output += f"  Severity: {cve['severity']}\n"
            output += f"  Affected Versions: {cve['versions_affected']}\n"
            output += f"  Description: {cve['description']}\n\n"

        return output
    except Exception as e:
        return f"Error: {str(e)}"


# =============================================================
# AGENT
# =============================================================

SYSTEM_PROMPT = """You are a professional penetration tester conducting an authorized
reconnaissance analysis. You are methodical, thorough, and systematic.

You have access to these tools:
1. read_file — read any challenge file (briefings, DNS, robots.txt, SSL info, etc.)
2. search_web — web search for OSINT
3. parse_nmap — parse pre-captured nmap XML scan results
4. analyze_headers — analyze HTTP response headers for security issues
5. check_cve — look up CVEs from a local vulnerability database

YOUR WORKFLOW (follow this order):
1. Read the briefing.txt file FIRST to understand the mission
2. Parse the nmap scan to identify open ports and services
3. For EACH service version found, check the CVE database
4. Analyze HTTP headers for misconfigurations
5. Read ALL remaining recon files (DNS, robots.txt, SSL info)
6. Look for flag fragments marked [FLAG_PART_N] in each file
7. Assemble all flag parts in order to form the complete flag

IMPORTANT:
- Do not skip any file — each one contains intelligence AND a flag fragment
- When you find a service version, ALWAYS check it against the CVE database
- Cross-reference findings: if nmap shows Apache 2.4.49 AND headers confirm it, note the correlation
- Your final output should be a structured threat assessment

FINAL OUTPUT FORMAT:
1. Executive Summary (2-3 sentences)
2. Critical Findings (with CVE IDs and CVSS scores)
3. Attack Surface Summary
4. Recommended Remediations (prioritized by severity)
5. ASSEMBLED FLAG from all [FLAG_PART_N] fragments"""

tools = [read_file, search_web, parse_nmap, analyze_headers, check_cve]
agent = create_react_agent(llm, tools)


# =============================================================
# RUN
# =============================================================

if __name__ == "__main__":
    print("🔍 CackalackyCon 2026 — Level 2: The Recon Agent")
    print("Multi-step reconnaissance analysis. Follow the briefing.\n")

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(
            content="""Begin your reconnaissance analysis.
Start by reading the briefing file at 'briefing.txt' for your mission objectives.
Then systematically analyze ALL data sources and produce your threat assessment.
Don't forget to collect all flag fragments!"""
        ),
    ]

    print("🚀 Agent starting reconnaissance...\n")

    try:
        result = agent.invoke({"messages": messages}, {"recursion_limit": 25})

        for msg in result["messages"]:
            if hasattr(msg, "content") and msg.content:
                role = msg.__class__.__name__
                if role == "AIMessage":
                    print(f"\n🤖 Agent:")
                    print(msg.content[:3000])
                elif role == "ToolMessage":
                    print(f"\n🔧 [{msg.name}] result:")
                    print(msg.content[:500])
                    if len(msg.content) > 500:
                        print("  ... (truncated)")

    except Exception as e:
        print(f"\n❌ Agent error: {str(e)}")
        print("Tip: Try increasing recursion_limit or simplifying your system prompt.")

    print("\n" + "=" * 60)