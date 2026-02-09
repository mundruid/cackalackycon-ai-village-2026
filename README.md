# cackalackycon-ai-village-2026

<p align="center">
  <img src="https://img.shields.io/badge/CackalackyCon-2026-orange?style=for-the-badge" alt="CackalackyCon 2026"/>
  <img src="https://img.shields.io/badge/AI_Village-Workshop-blue?style=for-the-badge" alt="AI Village"/>
  <img src="https://img.shields.io/badge/Cost-$0-brightgreen?style=for-the-badge" alt="Free"/>
</p>

# 🤖 Build Your Own Security Agent

### CackalackyCon 2026 AI Village — Hands-On Workshop

> Last year we watched AI demos. This year we **build** with it.

A 2-hour, hands-on workshop where you build AI agents that solve security challenges — entirely on your laptop, entirely for free. No cloud accounts. No API keys. No internet required during the workshop.

You'll use **Python**, **LangChain**, and **Ollama** (local LLMs) to build agents that crack CTF challenges, perform reconnaissance analysis, and run a multi-agent SOC response pipeline.

---

## 📋 What You'll Build

| Level | Name | Difficulty | What You Build |
|-------|------|------------|----------------|
| **L1** | The Solo Agent | 🟢 Beginner | Single agent with web search + file reader tools that solves CTF challenges (password cracking, OSINT, log analysis) |
| **L2** | The Recon Agent | 🟡 Intermediate | Multi-step agent that analyzes pre-captured nmap scans, HTTP headers, DNS records, and correlates CVEs |
| **L3** | The SOC Squad | 🔴 Advanced | Three agents (Triage → Threat Intel → Response Advisor) collaborating on incident response |

**Everyone** does Level 1. Levels 2 and 3 are for those who want to push further.

---

## ⚡ Pre-Work (REQUIRED — Do This Before the Conference)

> **There is limited internet at the venue. Models are multi-gigabyte downloads. You MUST complete this before arriving.**

### 1. Install Ollama

| Platform | Command |
|----------|---------|
| **macOS** | `brew install ollama` or download from [ollama.com](https://ollama.com/download) |
| **Linux** | `curl -fsSL https://ollama.com/install.sh \| sh` |
| **Windows** | Download installer from [ollama.com](https://ollama.com/download) |

Verify it installed:

```bash
ollama --version
```

### 2. Pull the Models

We use **Llama 3.1 8B** — an open-weight model from Meta that runs well on most laptops with 8GB+ RAM and has strong tool-calling support.

```bash
# Primary model (required) — ~4.7GB download
ollama pull llama3.1:8b

# Lightweight model for Level 3 multi-agent (required) — ~2GB download
ollama pull llama3.2:3b

# Verify it works
ollama run llama3.1:8b "Say 'ready' and nothing else."
```

Alternative recommended models:

- `qwen2.5:7B`: pretty good for agentic workflows and tool usage
- `mistral:7b`: strong tool calling capabilities as well 

<details>
<summary><strong>🔧 Hardware Guide (click to expand)</strong></summary>

| Your Laptop | Recommended Model | Notes |
|-------------|-------------------|-------|
| 8GB RAM, no GPU | `llama3.1:8b` | Will be slower but works fine. Close other apps. |
| 16GB RAM | `llama3.1:8b` | Smooth experience. |
| 16GB+ with GPU | `llama3.1:8b` | Fast. You could try `llama3.1:70b` at home later. |
| <8GB RAM | `llama3.2:3b` for everything | Smaller model, still capable. |
| Apple Silicon (M1/M2/M3/M4) | `llama3.1:8b` | Ollama uses Metal acceleration — runs great. |

If your model seems stuck or very slow, try: `ollama pull llama3.2:3b` and use that instead.

</details>

### 3. Install Python + uv

We use **[uv](https://docs.astral.sh/uv/)** — the fastest Python package manager. It handles Python versions and virtual environments automatically.

```bash
# Install uv (one command, no dependencies)
# macOS / Linux:
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell):
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### 4. Clone This Repo and Install Dependencies

```bash
git clone https://github.com/skisec/cackalacky-ai-village-2026.git
cd cackalacky-ai-village-2026

# This one command creates a venv, installs Python 3.12, and all dependencies:
uv sync
```

That's it. No `pip install`, no `venv` setup, no version conflicts. `uv sync` does everything.

### 5. Verify Your Setup

```bash
uv run python verify.py
```

You should see:

```
[✓] Ollama is running
[✓] llama3.1:8b model available
[✓] llama3.2:3b model available
[✓] LangChain installed
[✓] All challenge files present
🎉 You're ready for CackalackyCon 2026!
```

### Pre-Work Checklist

- [ ] Ollama installed and `ollama serve` running
- [ ] `llama3.1:8b` pulled (~4.7GB)
- [ ] `llama3.2:3b` pulled (~2GB)
- [ ] Repo cloned
- [ ] `uv sync` completed
- [ ] `uv run python verify.py` — all green

---

## 🏆 Competition: SOC Agent Showdown

In the last 15 minutes of the workshop, we'll run a live competition.

**L1 — "The Speed Solve":** Your agent solves a surprise challenge on the projector. Best reasoning + fastest flag wins.

**L2 — "Best Threat Brief":** Show your agent's threat assessment. Judged on completeness, CVE coverage, and "would you hand this to a CISO?"

**L3 — "SOC Squad Debrief":** Walk through your multi-agent pipeline and final incident report.

Everyone who participates gets a sticker. Winners get CackalackyCon challenge coins and bragging rights.

---

## 🛟 Troubleshooting

<details>
<summary><strong>Ollama says "connection refused"</strong></summary>

Ollama needs to be running as a server. Open a separate terminal and run:

```bash
ollama serve
```

Leave that terminal open. It needs to stay running.

</details>

<details>
<summary><strong>Model is very slow</strong></summary>

- Close browsers, Slack, Docker, and other memory-hungry apps
- Switch to the smaller model: change `llama3.1:8b` to `llama3.2:3b` in your agent code
- On Apple Silicon, make sure you're NOT running inside Rosetta

</details>

<details>
<summary><strong>Agent loops forever / never finishes</strong></summary>

Add a recursion limit to your agent invocation:

```python
result = agent.invoke({"messages": messages}, {"recursion_limit": 15})
```

</details>

<details>
<summary><strong>DuckDuckGo search tool fails</strong></summary>

This is expected if there's no internet! Your agent should still solve challenges 2, 3, and the bonus without web search — they only need the file reader tool.

</details>

<details>
<summary><strong>Windows-specific issues</strong></summary>

- Use PowerShell or WSL2, not CMD
- If `uv` isn't found after install, restart your terminal
- Path separators: the code uses `os.path.join()` which handles this automatically

</details>

<details>
<summary><strong>uv not working / prefer pip</strong></summary>

You can use pip instead:

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows
pip install langchain langchain-ollama langchain-core langgraph duckduckgo-search pandas
```

</details>

---

## 📚 Resources

- [Ollama Documentation](https://github.com/ollama/ollama)
- [LangChain + Ollama Integration](https://python.langchain.com/docs/integrations/llms/ollama/)
- [LangGraph Agent Tutorial](https://langchain-ai.github.io/langgraph/tutorials/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/) (for L2/L3 context)

---

## 📜 License

MIT — use this however you want. Build on it, teach from it, extend it.

If you do something cool with it, tell us at the [CackalackyCon Discord](https://discord.gg/a3zDHPG6be).

---

<p align="center">
  <strong>CackalackyCon 2026 AI Village</strong><br/>
  May 15–17 • Durham, NC<br/>
  <em>Last year we watched. This year we build.</em>
</p>
