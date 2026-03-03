<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-red?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Alpha-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/OWASP-LLM%20Top%2010-blue?style=for-the-badge" />
</p>

```
     ██████╗  █████╗ ███████╗██╗██╗     ██╗███████╗██╗  ██╗
     ██╔══██╗██╔══██╗██╔════╝██║██║     ██║██╔════╝██║ ██╔╝
     ██████╔╝███████║███████╗██║██║     ██║███████╗█████╔╝
     ██╔══██╗██╔══██║╚════██║██║██║     ██║╚════██║██╔═██╗
     ██████╔╝██║  ██║███████║██║███████╗██║███████║██║  ██╗
     ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝
                    AI Red Teaming Framework
```

# Basilisk

**The first open-source AI red teaming framework with genetic prompt evolution.**

Basilisk is a production-grade offensive security tool for red teaming AI/LLM applications. It combines comprehensive OWASP LLM Top 10 attack coverage with a novel genetic algorithm engine that **evolves prompt payloads across generations** to discover novel bypasses no static tool can find.

Built by [Regaan](https://regaan.rothackers.com) — the team behind [WSHawk](https://wshawk.rothackers.com) and PoCSmith.

---

## Features

### 🧬 Smart Prompt Evolution (SPE-NL)
The killer differentiator. Ported from WSHawk's Smart Payload Evolution engine, adapted for natural language:
- **10 mutation operators**: synonym swap, encoding wrap, role injection, language shift, structure overhaul, fragment split, nesting, homoglyphs, context padding, token smuggling
- **5 crossover strategies**: single-point, uniform, prefix-suffix, semantic blend, best-of-both
- **Multi-signal fitness function**: refusal avoidance, information leakage, compliance scoring, novelty reward
- **Stagnation detection** and early breakthrough exit

### ⚔️ 29 Attack Modules Across 8 Categories
| Category | Modules | OWASP |
|----------|---------|-------|
| **Prompt Injection** | Direct, Indirect, Multilingual, Encoding, Split | LLM01 |
| **System Prompt Extraction** | Role Confusion, Translation, Simulation, Gradient Walk | LLM06 |
| **Data Exfiltration** | Training Data, RAG Data, Tool Schema | LLM06 |
| **Tool/Function Abuse** | SSRF, SQLi, Command Injection, Chained | LLM07/08 |
| **Guardrail Bypass** | Roleplay, Encoding, Logic Trap, Systematic | LLM01 |
| **Denial of Service** | Token Exhaustion, Context Bomb, Loop Trigger | LLM04 |
| **Multi-Turn Manipulation** | Gradual Escalation, Persona Lock, Memory Manipulation | LLM01 |
| **RAG Attacks** | Poisoning, Document Injection, Knowledge Enumeration | LLM03/06 |

### 🔍 5-Module Reconnaissance
- Model fingerprinting (GPT-4, Claude, Gemini, Llama, Mistral)
- Guardrail profiling (8 content categories, benign→adversarial gradient)
- Tool/function discovery
- Context window measurement
- RAG pipeline detection

### 📊 Multi-Format Reporting
- **HTML** — Dark-themed, collapsible findings
- **SARIF 2.1.0** — CI/CD integration (GitHub Code Scanning, DefectDojo)
- **JSON** — Machine-readable
- **Markdown** — Documentation-ready

### 🌐 Universal Provider Support
Via `litellm` + custom adapters:
- OpenAI, Anthropic, Google, Azure, AWS Bedrock
- Ollama, vLLM (local models)
- Custom HTTP REST APIs
- WebSocket endpoints (pairs with WSHawk)

---

## Quick Start

```bash
# Install
pip install basilisk-ai

# Scan an OpenAI-powered chatbot
basilisk scan -t https://api.target.com/chat -p openai -k $OPENAI_API_KEY

# Quick scan (top payloads, no evolution)
basilisk scan -t https://api.target.com/chat --mode quick

# Deep scan with 10 evolution generations
basilisk scan -t https://api.target.com/chat --mode deep --generations 10

# Stealth mode (rate-limited, human-like timing)
basilisk scan -t https://api.target.com/chat --mode stealth

# Recon only
basilisk recon -t https://api.target.com/chat -p openai

# Specific modules only
basilisk scan -t https://api.target.com/chat --module injection --module extraction

# CI/CD mode with SARIF output
basilisk scan -t https://api.target.com/chat -o sarif --fail-on high
```

## Scan Modes

| Mode | Description | Evolution | Speed |
|------|-------------|-----------|-------|
| `quick` | Top 50 payloads, no evolution | ✗ | ⚡ Fast |
| `standard` | Full payloads, 5 generations | ✓ | 🔄 Normal |
| `deep` | Full payloads, 10+ generations, multi-turn | ✓✓ | 🐢 Slow |
| `stealth` | Rate-limited, human-like timing | ✓ | 🥷 Stealthy |
| `chaos` | Everything parallel, max evolution | ✓✓✓ | 💥 Aggressive |

## Configuration

Create a `basilisk.yaml` config file:

```yaml
target:
  url: https://api.target.com/chat
  provider: openai
  model: gpt-4
  api_key: ${OPENAI_API_KEY}

mode: standard

evolution:
  enabled: true
  population_size: 100
  generations: 5
  mutation_rate: 0.3
  crossover_rate: 0.5

output:
  format: html
  output_dir: ./reports
  include_conversations: true
```

```bash
basilisk scan -c basilisk.yaml
```

## Architecture

```
basilisk/
├── core/          # Engine: session, config, database, findings, profiles
├── providers/     # LLM adapters: litellm, custom HTTP, WebSocket
├── evolution/     # SPE-NL: genetic algorithm, operators, fitness, crossover
├── recon/         # Fingerprinting, guardrails, tools, context, RAG detection
├── attacks/       # 8 categories, 29 modules
│   ├── injection/
│   ├── extraction/
│   ├── exfil/
│   ├── toolabuse/
│   ├── guardrails/
│   ├── dos/
│   ├── multiturn/
│   └── rag/
├── cli/           # Click + Rich terminal interface
├── report/        # HTML, JSON, SARIF, Markdown generators
└── dashboard/     # FastAPI + WebSocket real-time UI (coming soon)
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: AI Security Scan
  run: |
    pip install basilisk-ai
    basilisk scan -t ${{ secrets.TARGET_URL }} -o sarif --fail-on high
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: basilisk-reports/*.sarif
```

## Legal

Basilisk is designed for **authorized security testing only**. Always obtain proper authorization before testing AI systems. Unauthorized use may violate computer fraud laws.

## License

MIT License — see [LICENSE](LICENSE)

---

**Built with 🐍 by [Regaan](https://regaan.rothackers.com)** — Offensive Security, Evolved.
