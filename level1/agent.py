"""
CackalackyCon 2026 — Level 1: The Solo Agent
=============================================

Build a security-focused agent with two tools:
  1. read_file — read challenge files from the challenges/ directory
  2. run_code  — execute Python code (with human approval)

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
    model="llama3.1:8b",  # Fast and capable for reasoning tasks
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
def read_file(file_path: str) -> str:
    """Read the contents of a challenge file. Use this to examine hints,
    log files, metadata, configuration files, or any text-based evidence.

    Input: a file path relative to the challenges/ directory.
           Examples: 'challenge1/hint.txt', 'challenge3/auth.log'
    Returns: the file contents (truncated to 5000 chars if very large).
    """
    try:
        # Strip leading "challenges/" if the LLM includes it (path is already relative to challenges/)
        file_path = file_path.removeprefix("challenges/")
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


@tool
def run_code(code: str) -> str:
    """Execute Python code to solve CTF challenges. Use this for decoding
    data (Base64, hex, ROT13, Caesar ciphers), parsing logs, computing hashes,
    or any analysis that requires computation.

    A human will review and approve the code before it runs.

    Input: a Python code snippet. Use print() to output results.
    Returns: the printed output from the code, or an error message.
    """
    import io
    import contextlib

    print(f"\n{'='*50}")
    print("🔍 AGENT WANTS TO RUN THIS CODE:")
    print(f"{'='*50}")
    print(code)
    print(f"{'='*50}")
    approval = input("✅ Allow execution? [y/N]: ").strip().lower()

    if approval != "y":
        return "Code execution denied by human operator."

    old_cwd = os.getcwd()
    stdout_capture = io.StringIO()
    try:
        os.chdir(CHALLENGES_DIR)
        with contextlib.redirect_stdout(stdout_capture):
            exec(code, {"__builtins__": __builtins__})
        output = stdout_capture.getvalue()
        return output if output else "(Code ran successfully but produced no output)"
    except Exception as e:
        return f"Code execution error: {type(e).__name__}: {str(e)}"
    finally:
        os.chdir(old_cwd)


# =============================================================
# STEP 3: Create the agent
# =============================================================
# The system prompt tells the LLM its role and how to approach problems.
# THIS IS WHERE YOU CAN EXPERIMENT — try different prompts and see how
# it changes the agent's behavior.

SYSTEM_PROMPT = """You are a cybersecurity CTF (Capture The Flag) solving agent.
You have access to three tools:
1. search_web — search the internet for security information
2. read_file — read challenge files from the challenges/ directory
3. run_code — execute Python code (a human will approve before it runs)

IMPORTANT RULES:
- ALWAYS use your tools by calling them. NEVER just describe what you would do.
- After reading a file, immediately call run_code to decode or analyze the data.
- Do NOT stop after reading a file. Keep going until you find the flag.
- When you see encoded data, call run_code with Python code to decode it.
- Flags are always in the format: FLAG{some_text_here}

Workflow for every challenge:
1. Call read_file to read the challenge file
2. Analyze what you see
3. Call run_code with Python code to decode/solve it
4. State the flag clearly"""

tools = [read_file, run_code]
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
        result = agent.invoke({"messages": messages}, {"recursion_limit": 50})

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
    # TODO: Write a prompt for the cipher challenge.
    #       Experiment: does hinting at the cipher type help the agent?
    # solve_challenge("""
    # TODO: Write your challenge prompt here.
    # The file is 'bonus/crypto_note.txt'.
    # """)
