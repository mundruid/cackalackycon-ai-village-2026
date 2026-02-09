"""
CackalackyCon 2026 — Level 1: The Solo Agent
=============================================

Build a security-focused agent with two tools:
  1. search_web — DuckDuckGo search for OSINT lookups
  2. read_file — read challenge files from the challenges/ directory

Your agent will solve CTF challenges using these tools.

Run with:
    uv run python level1/agent.py

Challenges:
    1. The Encoded Password    — decode a suspicious string
    2. Who Left This Behind?   — OSINT forensics from document metadata
    3. The Suspicious Login    — find the hidden message in auth logs
    BONUS: The Analyst's Note  — classic cipher challenge
"""

import os
from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.prebuilt import create_react_agent


# =============================================================
# STEP 1: Initialize your LLM
# =============================================================
# TODO: You can experiment with different models and temperatures.
#       Try llama3.2:3b if llama3.1:8b is too slow on your machine.

llm = ChatOllama(
    model="llama3.1:8b",
    temperature=0,  # Deterministic — good for CTF solving
)


# =============================================================
# STEP 2: Define your tools
# =============================================================
# These are the "hands" of your agent — the actions it can take.
# The docstrings are important! The LLM reads them to decide when
# to use each tool.

CHALLENGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenges")


@tool
def search_web(query: str) -> str:
    """Search the web using DuckDuckGo. Use this for OSINT lookups,
    researching CVEs, finding information about domains, IPs, hashes,
    or any cybersecurity intelligence gathering.

    Input: a search query string (e.g., 'RFC 4648 encoding scheme')
    Returns: top 3 search results with titles, URLs, and snippets.
    """
    try:
        from duckduckgo_search import DDGS

        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=3))
            if not results:
                return "No results found."
            output = ""
            for r in results:
                output += f"Title: {r['title']}\n"
                output += f"URL: {r['href']}\n"
                output += f"Snippet: {r['body']}\n\n"
            return output
    except Exception as e:
        return f"Search failed (no internet?): {str(e)}. Try solving without web search."


@tool
def read_file(file_path: str) -> str:
    """Read the contents of a challenge file. Use this to examine hints,
    log files, metadata, configuration files, or any text-based evidence.

    Input: a file path relative to the challenges/ directory.
           Examples: 'challenge1/hint.txt', 'challenge3/auth.log'
    Returns: the file contents (truncated to 5000 chars if very large).
    """
    try:
        safe_path = os.path.normpath(os.path.join(CHALLENGES_DIR, file_path))
        # Safety: only allow reading from the challenges directory
        if not safe_path.startswith(os.path.normpath(CHALLENGES_DIR)):
            return "Error: Access denied. You can only read files in the challenges/ directory."

        if not os.path.exists(safe_path):
            # Help the user find available files
            available = []
            for root, dirs, files in os.walk(CHALLENGES_DIR):
                for f in files:
                    rel = os.path.relpath(os.path.join(root, f), CHALLENGES_DIR)
                    available.append(rel)
            return f"File not found: {file_path}\nAvailable files:\n" + "\n".join(
                f"  - {f}" for f in available
            )

        with open(safe_path, "r") as f:
            content = f.read()
        return content[:5000]  # Limit for LLM context window
    except Exception as e:
        return f"Error reading file: {str(e)}"


# =============================================================
# STEP 3: Create the agent
# =============================================================
# The system prompt tells the LLM its role and how to approach problems.
# THIS IS WHERE YOU CAN EXPERIMENT — try different prompts and see how
# it changes the agent's behavior.

SYSTEM_PROMPT = """You are a cybersecurity CTF (Capture The Flag) solving agent.
You have access to two tools:
1. search_web — search the internet for security information
2. read_file — read challenge files from the challenges/ directory

When solving challenges:
- ALWAYS start by reading the challenge file to understand what you're working with
- Think step by step about what the clues mean
- Use your tools strategically — read files first, then search if you need more info
- Flags are always in the format: FLAG{some_text_here}
- Show your reasoning process clearly
- If you find the flag, state it clearly at the end

Be methodical. Be curious. Be precise."""

tools = [search_web, read_file]
agent = create_react_agent(llm, tools)


# =============================================================
# STEP 4: Run the agent against challenges
# =============================================================


def solve_challenge(challenge_description: str):
    """Send a challenge to the agent and print its full reasoning chain."""
    print("\n" + "=" * 60)
    print("📋 CHALLENGE:")
    print(challenge_description.strip())
    print("=" * 60)

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=challenge_description),
    ]

    try:
        result = agent.invoke({"messages": messages}, {"recursion_limit": 15})

        # Print the agent's reasoning chain
        for msg in result["messages"]:
            if hasattr(msg, "content") and msg.content:
                role = msg.__class__.__name__
                content = msg.content[:2000]

                if role == "AIMessage":
                    print(f"\n🤖 Agent:")
                    print(content)
                elif role == "ToolMessage":
                    print(f"\n🔧 Tool Result:")
                    print(content[:500])  # Truncate tool output for readability
                elif role == "HumanMessage":
                    pass  # We already printed the challenge

    except Exception as e:
        print(f"\n❌ Agent error: {str(e)}")
        print("Tip: If the agent is looping, try adjusting your system prompt.")

    print("\n" + "=" * 60 + "\n")


# =============================================================
# CHALLENGES
# =============================================================

if __name__ == "__main__":
    print("🤖 CackalackyCon 2026 — Level 1: The Solo Agent")
    print("Build a security agent. Solve the challenges. Find the flags.\n")

    # --- Challenge 1: The Encoded Password ---
    solve_challenge("""
    CHALLENGE 1: The Encoded Password

    An incident responder found an encoded string on a sticky note
    at a compromised workstation. Your job: decode it and find the flag.

    Read the file 'challenge1/hint.txt' to get started.
    """)

    # --- Uncomment each challenge as you solve the previous one ---

    # --- Challenge 2: Who Left This Behind? ---
    # solve_challenge("""
    # CHALLENGE 2: Who Left This Behind?
    #
    # A suspicious document was found on a finance team workstation.
    # Our forensics team extracted its metadata. Analyze it to identify
    # the threat actor and find the flag.
    #
    # Read the file 'challenge2/metadata.txt' to get started.
    # """)

    # --- Challenge 3: The Suspicious Login ---
    # solve_challenge("""
    # CHALLENGE 3: The Suspicious Login
    #
    # The SOC received an alert about unusual SSH activity.
    # Analyze the authentication logs to identify the brute-force attack
    # and find the hidden message in the attacker's attempts.
    #
    # Read the file 'challenge3/auth.log' to get started.
    # """)

    # --- BONUS: The Analyst's Note ---
    # solve_challenge("""
    # BONUS CHALLENGE: The Analyst's Note
    #
    # A senior analyst left an encrypted note before going on vacation.
    # It uses a cipher that Julius Caesar's "simpler cousin" would appreciate.
    #
    # Read the file 'bonus/crypto_note.txt' to get started.
    # """)