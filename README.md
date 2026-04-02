<p align="center">
  <img src="assets/banner.png" alt="OffensiveSET" width="700">
</p>

<h1 align="center">OffensiveSET</h1>

<p align="center">
  <strong>Offensive Security Dataset Generator</strong> — An MCP server that generates high-quality, multi-turn pentesting conversation datasets for fine-tuning security-focused LLMs.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-red?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/scenarios-45-blue?style=flat-square" alt="Scenarios">
  <img src="https://img.shields.io/badge/tools-40-blue?style=flat-square" alt="Tools">
  <img src="https://img.shields.io/badge/MCP-compatible-green?style=flat-square" alt="MCP">
  <img src="https://img.shields.io/badge/Qwen3.5-optimized-orange?style=flat-square" alt="Qwen">
  <img src="https://img.shields.io/badge/license-MIT-gray?style=flat-square" alt="License">
</p>

Built for training models like Qwen3.5 to think and act like professional penetration testers.

---

## What It Does

OffensiveSET generates realistic penetration testing conversations in ShareGPT/ChatML JSONL format. Each entry is a complete pentest engagement — from reconnaissance to exploitation to professional reporting — with:

- **Multi-turn conversations** (8-15 turns) following real pentester workflows
- **Chain-of-thought reasoning** via `<think>` blocks modeling how pentesters analyze attack surfaces
- **Realistic tool outputs** — unique nmap scans, sqlmap dumps, nuclei findings per entry (no duplicates)
- **Failure cases** — blocked attacks, WAF bypasses, honeypot detection, and pivoting strategies
- **Professional reports** — CVSS scoring, CWE references, evidence PoCs, and secure code remediation
- **Qwen3.5 native format** — `observation` role, `<tool_call>` tags, inline `<think>` reasoning

---

## Stats

| Metric | Value |
|--------|-------|
| Attack scenarios | 45 |
| Pentesting tools | 40 |
| Dynamic output generators | 25 |
| User prompt templates | 120+ |
| Target domains | 50 |
| Failure patterns | 13 |
| Export formats | 5 (Qwen ChatML, Generic ChatML, ShareGPT, OpenAI, Alpaca) |

---

## Quick Start

### Install & Setup

```bash
git clone https://github.com/PentesterFlow/OffensiveSET.git
cd OffensiveSET
npm install
npm run build
```

### Claude Code (CLI) — Quickest Setup

```bash
# Add the MCP server (run from inside the cloned repo)
claude mcp add offensiveset node $(pwd)/dist/index.js

# Verify
claude mcp list

# Start using it
claude
```

### Claude Desktop (GUI)

Open your MCP config file:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Add this block (update the path to where you cloned the repo):

```json
{
  "mcpServers": {
    "offensiveset": {
      "command": "node",
      "args": ["/Users/YOUR_USER/OffensiveSET/dist/index.js"]
    }
  }
}
```

Restart Claude Desktop. The 10 OffensiveSET tools will appear in the tools menu.

### VS Code / JetBrains (Claude Code Extension)

```bash
# From the integrated terminal
claude mcp add offensiveset node /path/to/OffensiveSET/dist/index.js
```

Or add a `.mcp.json` to your project root:

```json
{
  "mcpServers": {
    "offensiveset": {
      "command": "node",
      "args": ["/path/to/OffensiveSET/dist/index.js"]
    }
  }
}
```

### One-Line Install (Clone + Build + Register)

```bash
git clone https://github.com/PentesterFlow/OffensiveSET.git && cd OffensiveSET && npm install && npm run build && claude mcp add offensiveset node $(pwd)/dist/index.js
```

### Generate a Dataset

Once connected, ask Claude to use the tools:

```
> Generate a 5000 entry offensive security dataset with 60% thinking blocks

> List all available attack scenarios

> Preview a single entry for the NoSQL injection scenario

> Export my dataset to Qwen ChatML format
```

Or call tools directly:

```
generate_dataset_v2
  count: 5000
  thinking_ratio: 0.6
  failure_ratio: 0.35
  thinking_style: "inline"
```

### Export for Training

```
export_for_training
  input_path: "./datasets/your_dataset.jsonl"
  output_format: "chatml_qwen"
```

---

## MCP Tools

| Tool | Description |
|------|-------------|
| `generate_dataset` | V1 generator — baseline pentesting conversations |
| `generate_dataset_v2` | V2 generator — dynamic outputs, failures, deep thinking (recommended) |
| `list_scenarios` | Browse 45 attack scenarios with filtering |
| `list_tools` | Display 40 pentesting tools and capabilities |
| `preview_entry` | Preview a single entry before full generation |
| `get_dataset_stats` | Analyze a generated dataset |
| `validate_dataset` | Check JSONL structure, schema compliance, placeholder detection |
| `quality_score` | Deep quality analysis with A-F grading |
| `export_for_training` | Convert to Qwen ChatML, ShareGPT, OpenAI, or Alpaca format |
| `merge_datasets` | Combine multiple datasets with deduplication |

---

## Dataset Output Format

Each JSONL line is a complete pentesting conversation:

```json
{
  "id": "offensiveset-owasp-a03-sqli-584721-42",
  "conversations": [
    {"from": "system", "value": "You are PentesterFlow, an expert offensive security AI..."},
    {"from": "human", "value": "Perform recon on acme-corp.com..."},
    {"from": "gpt", "value": "<think>\nLet me analyze the attack surface...\n</think>\n\n## Recon Results\n...", "tool_calls": [...]},
    {"from": "observation", "value": "[nmap] PORT STATE SERVICE...", "tool_results": [...]},
    {"from": "human", "value": "Exploit the SQLi finding..."},
    {"from": "gpt", "value": "<think>\nThe parameter is injectable...\n</think>\n\n## Exploitation\n..."},
    {"from": "gpt", "value": "## Finding Report\n| Severity | Critical 9.8 | ..."}
  ],
  "metadata": {
    "scenario_id": "owasp-a03-sqli",
    "category": "OWASP Top 10",
    "difficulty": "advanced",
    "tags": ["sqli", "injection"],
    "tools_used": ["nmap", "sqlmap", "curl"],
    "has_thinking": true,
    "has_failures": false,
    "turn_count": 12,
    "estimated_tokens": 4606,
    "cve_references": ["CWE-89"]
  }
}
```

---

## Scenario Coverage

### OWASP Top 10 (19 scenarios)
IDOR, Admin Panel Bypass, JWT Algorithm Confusion, Blind SQL Injection, SSTI to RCE, Business Logic Flaws, Cloud Misconfiguration, Stored XSS, NoSQL Injection, XXE, Path Traversal, File Upload RCE, Mass Assignment, CRLF Injection, LDAP Injection, OAuth Token Theft, 2FA Bypass, Deserialization RCE

### Modern Attacks (20 scenarios)
GraphQL Batching, HTTP Request Smuggling, Prototype Pollution, Race Conditions, WebSocket Hijacking, Subdomain Takeover, CORS Exploitation, Cache Poisoning, CI/CD Pipeline Attacks, Container Escape, DNS Rebinding, Kubernetes RBAC Escape, GitHub Actions Secret Exfiltration

### API Security Top 10 (6 scenarios)
BOLA + Mass Assignment, Excessive Data Exposure, Broken Function Level Authorization, Rate Limit Bypass

---

## Tool Arsenal (40 tools)

**Recon:** nmap, subfinder, amass, httpx, rustscan, puredns, dnsx

**Enumeration:** ffuf, gobuster, dirsearch, feroxbuster, katana, kiterunner, linkfinder, paramspider, gau, arjun

**Scanning:** nuclei, nikto, wfuzz, trufflehog, semgrep, crlfuzz, corsy, secretfinder, testssl

**Exploitation:** sqlmap, dalfox, commix, ssrfmap, jwt_tool, hydra, metasploit, caido, interactsh, nosqlmap

**Utility:** curl, linpeas, report_generator, gf

---

## Training with Qwen3.5

### LLaMA-Factory

```yaml
# dataset_info.json
{
  "offensiveset": {
    "file_name": "dataset_chatml_qwen.jsonl",
    "formatting": "sharegpt",
    "columns": {
      "messages": "messages"
    },
    "tags": {
      "role_tag": "role",
      "content_tag": "content",
      "user_tag": "user",
      "assistant_tag": "assistant",
      "observation_tag": "observation",
      "system_tag": "system"
    }
  }
}
```

```bash
llamafactory-cli train \
  --model_name_or_path Qwen/Qwen3.5-7B \
  --stage sft \
  --dataset offensiveset \
  --template qwen \
  --output_dir ./offensiveset-model \
  --per_device_train_batch_size 2 \
  --gradient_accumulation_steps 8 \
  --learning_rate 1e-4 \
  --num_train_epochs 3 \
  --cutoff_len 8192 \
  --finetuning_type lora \
  --lora_rank 64 \
  --bf16 true
```

### Recommended Settings

| Setting | Value | Notes |
|---------|-------|-------|
| Model | Qwen3.5-7B or 14B | Best quality/cost balance |
| Context | 8192 tokens | 97% of entries fit in 8K |
| Epochs | 2-3 | Enough for domain knowledge |
| LoRA rank | 64-128 | Security is a specialized domain |
| Thinking style | `inline` | Qwen native `<think>` format |

---

## Project Structure

```
src/
├── index.ts                          # Entry point (34 lines)
├── server/
│   ├── generate-tools.ts             # generate_dataset, generate_dataset_v2
│   ├── browse-tools.ts               # list_scenarios, list_tools, preview
│   ├── analysis-tools.ts             # stats, validate, quality_score
│   ├── export-tools.ts               # export, merge
│   └── resources.ts                  # MCP resources
├── generators/
│   ├── v1-generator.ts               # V1 generation engine
│   ├── v2/
│   │   ├── types.ts                  # Interfaces + config
│   │   ├── prompts.ts                # 120+ prompt templates
│   │   ├── system-prompts.ts         # System prompt rotation
│   │   ├── responses.ts             # Grounded response generation
│   │   ├── reports.ts                # Reports + remediation
│   │   ├── conversation.ts           # Conversation builder
│   │   ├── post-processor.ts         # Qwen compat + token control
│   │   ├── quality.ts                # Quality scoring engine
│   │   └── index.ts                  # Main generator
│   ├── outputs/
│   │   ├── helpers.ts                # RNG, TargetProfile, constants
│   │   ├── recon.ts                  # nmap, rustscan, subfinder...
│   │   ├── enum.ts                   # ffuf, feroxbuster, katana...
│   │   ├── vuln.ts                   # nuclei, semgrep, testssl...
│   │   ├── exploit.ts                # sqlmap, hydra, metasploit...
│   │   ├── cloud.ts                  # S3, env files
│   │   ├── failures.ts               # 13 failure patterns
│   │   └── index.ts                  # DynamicOutputEngine
│   └── thinking-engine.ts            # Chain-of-thought reasoning
├── templates/
│   └── scenarios/
│       ├── types.ts                  # ScenarioTemplate interface
│       ├── owasp.ts                  # OWASP Top 10 scenarios
│       ├── modern.ts                 # Modern attacks
│       ├── api.ts                    # API Security scenarios
│       ├── advanced.ts               # Advanced scenarios
│       └── index.ts                  # ALL_SCENARIOS
└── schemas/
    └── tools/
        ├── types.ts                  # ToolDefinition interface
        ├── recon.ts                  # Recon tools
        ├── enum.ts                   # Enumeration tools
        ├── scan.ts                   # Scanning tools
        ├── exploit.ts                # Exploitation tools
        ├── utility.ts                # Utility tools
        └── index.ts                  # PENTESTING_TOOLS
```

---

## Adding New Content

### Add a Scenario

Edit `src/templates/scenarios/advanced.ts` (or create a new category file):

```typescript
{
  id: "my-new-scenario",
  category: "OWASP Top 10",
  subcategory: "A03 - Injection",
  title: "My Custom Injection Scenario",
  difficulty: "advanced",
  description: "...",
  target_description: "...",
  attack_phases: [ /* 4-6 phases */ ],
  cve_references: ["CWE-89"],
  tools_involved: ["sqlmap", "curl"],
  tags: ["sqli", "injection"],
}
```

### Add a Tool

Edit the relevant category file in `src/schemas/tools/`:

```typescript
{
  name: "mytool",
  description: "...",
  category: "scanning",
  parameters: { /* ... */ },
  example_commands: ["mytool -u https://target.com"],
  typical_output: "...",
}
```

### Add a Dynamic Output Generator

Add a method to `src/generators/outputs/` in the appropriate category file, then register it in `src/generators/outputs/index.ts`.

---

## License

MIT

---

## Author

**secfathy** — Offensive Security Researcher

Built with Claude Code.
