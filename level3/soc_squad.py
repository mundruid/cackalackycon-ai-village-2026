"""
CackalackyCon 2026 — Level 3: The SOC Squad
=============================================

Three specialized agents collaborate on incident response:
  1. Triage Agent       — reads logs, identifies IOCs, classifies the incident
  2. Threat Intel Agent — enriches IOCs with local threat intelligence
  3. Response Advisor   — produces an incident response playbook

Uses LangGraph for multi-agent orchestration.

Run with:
    uv run python level3/soc_squad.py
"""

import os
import json
from typing import TypedDict
from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.prebuilt import create_react_agent
from langgraph.graph import StateGraph, END


# =============================================================
# CONFIG
# =============================================================

# Using the smaller model — 3 agents means 3x the inference work.
# llama3.2:3b is fast and focused enough for specialized tasks.
# If you have 16GB+ RAM, try llama3.1:8b for better results.
MODEL = "llama3.2:3b"

llm = ChatOllama(model=MODEL, temperature=0)
CHALLENGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenges")


# =============================================================
# SHARED STATE
# =============================================================
# This is how agents pass information to each other.
# Each agent reads from previous agents' outputs and writes its own.


class SOCState(TypedDict):
    incident_data: str  # Raw incident data path info
    triage_report: str  # Output from Triage Agent
    enriched_iocs: str  # Output from Threat Intel Agent
    response_plan: str  # Output from Response Advisor
    final_report: str  # Combined final report
    current_agent: str  # Tracking which agent is active


# =============================================================
# TOOLS
# =============================================================


@tool
def read_incident_file(file_path: str) -> str:
    """Read an incident data file (SIEM alerts, firewall logs, endpoint logs).
    Input: file path relative to the challenges/ directory.
    Examples: 'incident/siem_alerts.json', 'incident/firewall_logs.txt'
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
            return f"Not found: {file_path}\nAvailable:\n" + "\n".join(
                f"  - {f}" for f in available
            )
        with open(safe_path, "r") as f:
            return f.read()[:8000]
    except Exception as e:
        return f"Error: {str(e)}"


@tool
def lookup_threat_intel(ioc: str) -> str:
    """Look up an indicator of compromise in the local threat intelligence database.
    Input: an IOC — IP address, domain, hash, filename, or tool name.
    Examples: '198.51.100.23', 'beacon.sh', 'wmiexec.py'
    """
    try:
        db_path = os.path.join(CHALLENGES_DIR, "threat_intel_db.json")
        with open(db_path, "r") as f:
            ti_db = json.load(f)

        ioc_lower = ioc.lower().strip()
        matches = []

        for entry in ti_db:
            if ioc_lower in entry.get("indicator", "").lower():
                matches.append(entry)

        if not matches:
            return f"No threat intelligence found for: {ioc}"

        output = f"=== Threat Intel Results for '{ioc}' ===\n"
        for m in matches:
            output += f"  Indicator: {m['indicator']}\n"
            output += f"  Type: {m['type']}\n"
            output += f"  Threat Actor: {m['threat_actor']}\n"
            output += f"  Campaign: {m['campaign']}\n"
            output += f"  Confidence: {m['confidence']}\n"
            output += f"  First Seen: {m['first_seen']}\n"
            output += f"  Tags: {', '.join(m['tags'])}\n\n"
        return output
    except Exception as e:
        return f"Error: {str(e)}"


@tool
def check_ir_playbook(incident_type: str) -> str:
    """Look up the incident response playbook for a given incident type.
    Input: incident type — 'brute_force', 'data_exfiltration', or 'lateral_movement'.
    """
    playbooks = {
        "brute_force": {
            "severity": "MEDIUM-HIGH",
            "immediate": [
                "Block attacker IP at perimeter firewall",
                "Force password reset for all targeted accounts",
                "Enable account lockout policies if not already active",
                "Review successful authentications from attacker IP",
            ],
            "investigation": [
                "Determine if any brute force attempts succeeded",
                "Check for lateral movement from compromised accounts",
                "Review auth logs for past 30 days for the attacker IP",
                "Identify all accounts targeted in the attack",
            ],
            "containment": [
                "Isolate any compromised hosts from the network",
                "Revoke all active sessions for compromised accounts",
                "Implement geo-blocking if attacker IP is foreign",
                "Deploy MFA on all targeted accounts immediately",
            ],
        },
        "data_exfiltration": {
            "severity": "CRITICAL",
            "immediate": [
                "Isolate affected systems from the network IMMEDIATELY",
                "Block destination IPs/domains at perimeter firewall",
                "Preserve all forensic evidence (do NOT reboot systems)",
                "Notify incident commander and legal team",
            ],
            "investigation": [
                "Identify exactly what data was exfiltrated (PII, trade secrets, etc.)",
                "Determine exfiltration method, volume, and duration",
                "Trace the full lateral movement path from initial access to exfil",
                "Identify the initial access vector (how did they get in?)",
            ],
            "containment": [
                "Network segmentation of all affected zones",
                "Kill all malicious processes and remove persistence",
                "Reset ALL credentials on affected systems and accounts",
                "If PII involved: begin legal/compliance breach notification process",
            ],
        },
        "lateral_movement": {
            "severity": "HIGH",
            "immediate": [
                "Identify ALL systems accessed by the threat actor",
                "Isolate compromised hosts from the network",
                "Block internal pivot IPs at micro-segmentation layer",
                "Capture memory dumps of affected systems before remediation",
            ],
            "investigation": [
                "Map the full scope of lateral movement (every hop)",
                "Identify all credentials used or compromised",
                "Determine the initial compromise vector",
                "Hunt for persistence mechanisms on every touched system",
            ],
            "containment": [
                "Reset all credentials for affected and adjacent accounts",
                "Implement emergency network micro-segmentation",
                "Deploy EDR agents to all affected endpoints",
                "Conduct threat hunt across the full environment for additional IOCs",
            ],
        },
    }

    incident_lower = incident_type.lower().strip()
    for key, playbook in playbooks.items():
        if key in incident_lower or incident_lower in key:
            output = f"=== INCIDENT RESPONSE PLAYBOOK: {key.upper()} ===\n"
            output += f"Severity: {playbook['severity']}\n\n"
            output += "IMMEDIATE ACTIONS (next 15 min):\n"
            for i, a in enumerate(playbook["immediate"], 1):
                output += f"  {i}. {a}\n"
            output += "\nINVESTIGATION STEPS:\n"
            for i, a in enumerate(playbook["investigation"], 1):
                output += f"  {i}. {a}\n"
            output += "\nCONTAINMENT & REMEDIATION:\n"
            for i, a in enumerate(playbook["containment"], 1):
                output += f"  {i}. {a}\n"
            return output

    available = ", ".join(playbooks.keys())
    return f"No playbook for '{incident_type}'. Available types: {available}"


# =============================================================
# AGENT NODES
# =============================================================


def triage_agent(state: SOCState) -> SOCState:
    """Agent 1: Triage — reads all incident data, identifies IOCs, classifies the incident."""
    print("\n🔎 TRIAGE AGENT: Analyzing incident data...")

    # =================================================================
    # TODO: Write the TRIAGE AGENT prompts here!
    # =================================================================
    # The Triage Agent is Agent 1 in the pipeline. Its job:
    #   - Read ALL incident files (siem_alerts.json, firewall_logs.txt, endpoint_logs.txt)
    #   - Identify indicators of compromise (IOCs): IPs, files, behaviors
    #   - Classify the incident type (brute_force, lateral_movement, data_exfiltration)
    #   - Create a structured triage report for the next agent
    #
    # Your SYSTEM prompt should define:
    #   - The agent's role (SOC Triage Analyst)
    #   - Which files to read
    #   - The output format (classification, severity, IOCs, timeline, etc.)
    #
    # Your USER message should:
    #   - Instruct the agent to begin analysis
    #
    TRIAGE_SYSTEM_PROMPT = """
YOUR TRIAGE SYSTEM PROMPT HERE
"""
    TRIAGE_USER_MESSAGE = """
YOUR TRIAGE USER MESSAGE HERE
"""

    messages = [
        SystemMessage(content=TRIAGE_SYSTEM_PROMPT),
        HumanMessage(content=TRIAGE_USER_MESSAGE),
    ]

    triage = create_react_agent(llm, [read_incident_file])

    try:
        result = triage.invoke({"messages": messages}, {"recursion_limit": 15})
        final_msg = result["messages"][-1].content if result["messages"] else "Triage failed."
    except Exception as e:
        final_msg = f"Triage agent error: {str(e)}"

    print(f"\n📋 Triage Report:\n{final_msg[:1000]}...")

    state["triage_report"] = final_msg
    state["current_agent"] = "threat_intel"
    return state


def threat_intel_agent(state: SOCState) -> SOCState:
    """Agent 2: Threat Intel — enriches IOCs from the triage report."""
    print("\n🌐 THREAT INTEL AGENT: Enriching IOCs...")

    # =================================================================
    # TODO: Write the THREAT INTEL AGENT prompts here!
    # =================================================================
    # The Threat Intel Agent is Agent 2 in the pipeline. Its job:
    #   - Extract IOCs from the triage report (passed in state)
    #   - Look up EACH IOC using the lookup_threat_intel tool
    #   - Identify threat actor, campaign, and TTPs
    #   - Produce an enriched intelligence report
    #
    # Your SYSTEM prompt should define:
    #   - The agent's role (Threat Intelligence Analyst)
    #   - Instructions to look up every IOC
    #   - The output format (threat actor, campaign, enriched IOCs, TTPs)
    #
    # Your USER message should:
    #   - Pass the triage report from the previous agent
    #   - Instruct enrichment of each IOC
    #
    # Note: The triage report is available in state['triage_report']
    #
    INTEL_SYSTEM_PROMPT = """
YOUR THREAT INTEL SYSTEM PROMPT HERE
"""
    INTEL_USER_MESSAGE = f"""
YOUR THREAT INTEL USER MESSAGE HERE

TRIAGE REPORT:
{state['triage_report'][:3000]}
"""

    messages = [
        SystemMessage(content=INTEL_SYSTEM_PROMPT),
        HumanMessage(content=INTEL_USER_MESSAGE),
    ]

    intel = create_react_agent(llm, [lookup_threat_intel])

    try:
        result = intel.invoke({"messages": messages}, {"recursion_limit": 15})
        final_msg = result["messages"][-1].content if result["messages"] else "Intel failed."
    except Exception as e:
        final_msg = f"Intel agent error: {str(e)}"

    print(f"\n📋 Intel Report:\n{final_msg[:1000]}...")

    state["enriched_iocs"] = final_msg
    state["current_agent"] = "response_advisor"
    return state


def response_advisor_agent(state: SOCState) -> SOCState:
    """Agent 3: Response Advisor — produces the incident response plan."""
    print("\n🛡️ RESPONSE ADVISOR: Building incident response plan...")

    # =================================================================
    # TODO: Write the RESPONSE ADVISOR AGENT prompts here!
    # =================================================================
    # The Response Advisor is Agent 3 in the pipeline. Its job:
    #   - Review triage report AND enriched threat intel (both in state)
    #   - Look up IR playbooks using check_ir_playbook tool
    #   - Produce a customized incident response plan
    #
    # Your SYSTEM prompt should define:
    #   - The agent's role (Senior Incident Response Advisor)
    #   - Instructions to look up playbooks for each incident type
    #   - The output format (phased response plan with specific actions)
    #   - Instructions for the FLAG (combine threat actor + campaign)
    #
    # Your USER message should:
    #   - Pass both the triage report and threat intel from previous agents
    #   - Instruct the agent to build the response plan
    #
    # Note: Available playbook types: brute_force, lateral_movement, data_exfiltration
    #
    RESPONSE_SYSTEM_PROMPT = """
YOUR RESPONSE ADVISOR SYSTEM PROMPT HERE
"""
    RESPONSE_USER_MESSAGE = f"""
YOUR RESPONSE ADVISOR USER MESSAGE HERE

TRIAGE REPORT:
{state['triage_report'][:2000]}

THREAT INTELLIGENCE:
{state['enriched_iocs'][:2000]}
"""

    messages = [
        SystemMessage(content=RESPONSE_SYSTEM_PROMPT),
        HumanMessage(content=RESPONSE_USER_MESSAGE),
    ]

    advisor = create_react_agent(llm, [check_ir_playbook])

    try:
        result = advisor.invoke({"messages": messages}, {"recursion_limit": 15})
        final_msg = result["messages"][-1].content if result["messages"] else "Response plan failed."
    except Exception as e:
        final_msg = f"Advisor agent error: {str(e)}"

    print(f"\n📋 Response Plan:\n{final_msg[:1000]}...")

    state["response_plan"] = final_msg
    state["current_agent"] = "done"
    return state


def compile_report(state: SOCState) -> SOCState:
    """Final step: combine all agent outputs into a single report."""
    divider = "=" * 60
    state["final_report"] = f"""
{divider}
🛡️  CACKALACKYCON SOC SQUAD — INCIDENT RESPONSE REPORT
{divider}

SECTION 1: TRIAGE ANALYSIS
{'-' * 40}
{state['triage_report']}

{divider}

SECTION 2: THREAT INTELLIGENCE
{'-' * 40}
{state['enriched_iocs']}

{divider}

SECTION 3: INCIDENT RESPONSE PLAN
{'-' * 40}
{state['response_plan']}

{divider}
Report compiled by: CackalackyCon SOC Squad (3-agent pipeline)
Model: {MODEL}
{divider}
"""
    return state


# =============================================================
# BUILD THE MULTI-AGENT GRAPH
# =============================================================


def build_soc_graph():
    """Build a LangGraph workflow: Triage → Intel → Response → Compile"""
    workflow = StateGraph(SOCState)

    workflow.add_node("triage", triage_agent)
    workflow.add_node("threat_intel", threat_intel_agent)
    workflow.add_node("response_advisor", response_advisor_agent)
    workflow.add_node("compile", compile_report)

    workflow.set_entry_point("triage")
    workflow.add_edge("triage", "threat_intel")
    workflow.add_edge("threat_intel", "response_advisor")
    workflow.add_edge("response_advisor", "compile")
    workflow.add_edge("compile", END)

    return workflow.compile()


# =============================================================
# RUN
# =============================================================

if __name__ == "__main__":
    print("🛡️  CackalackyCon 2026 — Level 3: The SOC Squad")
    print(f"   Multi-agent incident response pipeline (model: {MODEL})")
    print(f"   3 agents: Triage → Threat Intel → Response Advisor\n")

    graph = build_soc_graph()

    initial_state: SOCState = {
        "incident_data": "challenges/incident/",
        "triage_report": "",
        "enriched_iocs": "",
        "response_plan": "",
        "final_report": "",
        "current_agent": "triage",
    }

    print("🚀 Launching SOC Squad...\n")
    result = graph.invoke(initial_state)

    print("\n\n" + result["final_report"])