#!/usr/bin/env python3
"""
CackalackyCon 2026 AI Village — Pre-Work Verification Script
Run this to confirm your setup is ready for the workshop.

Usage:
    uv run python verify.py
"""

import os
import sys
import json
import subprocess

BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

PASS = f"{GREEN}[✓]{RESET}"
FAIL = f"{RED}[✗]{RESET}"
WARN = f"{YELLOW}[!]{RESET}"

errors = []
warnings = []


def check(label: str, condition: bool, error_msg: str = "", warn_only: bool = False):
    if condition:
        print(f"  {PASS} {label}")
    elif warn_only:
        print(f"  {WARN} {label} — {error_msg}")
        warnings.append(error_msg)
    else:
        print(f"  {FAIL} {label} — {error_msg}")
        errors.append(error_msg)


def check_ollama_running() -> bool:
    try:
        import urllib.request
        req = urllib.request.Request("http://localhost:11434/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def get_ollama_models() -> list[str]:
    try:
        import urllib.request
        req = urllib.request.Request("http://localhost:11434/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


def check_model_available(model_name: str, models: list[str]) -> bool:
    # Match "llama3.1:8b" against "llama3.1:8b", "llama3.1:8b-instruct-q4_0", etc.
    return any(model_name in m for m in models)


def main():
    print()
    print(f"{BOLD}🤖 CackalackyCon 2026 AI Village — Setup Verification{RESET}")
    print(f"{'=' * 55}")
    print()

    # --- Ollama ---
    print(f"{BOLD}Ollama:{RESET}")
    ollama_running = check_ollama_running()
    check("Ollama is running", ollama_running,
          "Run 'ollama serve' in a separate terminal")

    if ollama_running:
        models = get_ollama_models()
        check("llama3.1:8b model available",
              check_model_available("llama3.1", models),
              "Run: ollama pull llama3.1:8b")
        check("llama3.2:3b model available",
              check_model_available("llama3.2", models),
              "Run: ollama pull llama3.2:3b",
              warn_only=True)
    else:
        print(f"  {FAIL} Skipping model checks (Ollama not running)")
        errors.append("Ollama not running — can't check models")

    print()

    # --- Python Packages ---
    print(f"{BOLD}Python Packages:{RESET}")

    packages = {
        "langchain": "langchain",
        "langchain_ollama": "langchain-ollama",
        "langchain_core": "langchain-core",
        "langgraph": "langgraph",
        "duckduckgo_search": "duckduckgo-search",
        "pandas": "pandas",
    }

    for import_name, pip_name in packages.items():
        try:
            __import__(import_name)
            check(f"{pip_name} installed", True)
        except ImportError:
            check(f"{pip_name} installed", False,
                  f"Run: uv sync (or pip install {pip_name})")

    print()

    # --- Challenge Files ---
    print(f"{BOLD}Challenge Files:{RESET}")

    repo_root = os.path.dirname(os.path.abspath(__file__))
    required_files = [
        "level1/agent.py",
        "level1/challenges/challenge1/hint.txt",
        "level1/challenges/challenge2/metadata.txt",
        "level1/challenges/challenge3/encoded.txt",
        "level1/challenges/bonus/crypto_note.txt",
        "level2/challenges/recon/agent.py",
        "level2/challenges/recon/briefing.txt",
        "level2/challenges/recon/cve_database.json",
        "level2/challenges/recon/data/scan_results.xml",
        "level2/challenges/recon/data/http_headers.txt",
        "level2/challenges/recon/data/ssl_info.txt",
        "level2/challenges/malware/agent.py",
        "level2/challenges/malware/briefing.txt",
        "level2/challenges/malware/ttp_db.json",
        "level2/challenges/malware/data/dropper.ps1",
        "level2/challenges/malware/data/beacon.py",
        "level2/challenges/malware/data/persist.sh",
        "level3/soc_squad.py",
        "level3/challenges/threat_intel_db.json",
        "level3/challenges/incident/siem_alerts.json",
    ]

    for filepath in required_files:
        full_path = os.path.join(repo_root, filepath)
        check(filepath, os.path.exists(full_path), "File missing — try: git pull")

    print()

    # --- LLM Quick Test ---
    if ollama_running and check_model_available("llama3.1", get_ollama_models()):
        print(f"{BOLD}LLM Quick Test:{RESET}")
        try:
            from langchain_ollama import ChatOllama
            llm = ChatOllama(model="llama3.1:8b", temperature=0)
            response = llm.invoke("Respond with only the word: READY")
            got_response = len(response.content.strip()) > 0
            check("LLM responds to prompts", got_response, "Model returned empty response")
        except Exception as e:
            check("LLM responds to prompts", False, str(e)[:80])
        print()

    # --- Summary ---
    print(f"{'=' * 55}")
    if not errors and not warnings:
        print(f"{GREEN}{BOLD}🎉 You're ready for CackalackyCon 2026!{RESET}")
    elif not errors:
        print(f"{YELLOW}{BOLD}⚠️  Almost ready — {len(warnings)} warning(s) (non-blocking){RESET}")
        for w in warnings:
            print(f"  {WARN} {w}")
    else:
        print(f"{RED}{BOLD}❌ {len(errors)} issue(s) to fix:{RESET}")
        for e in errors:
            print(f"  {FAIL} {e}")
        if warnings:
            print(f"{YELLOW}  + {len(warnings)} warning(s):{RESET}")
            for w in warnings:
                print(f"  {WARN} {w}")
    print()

    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())