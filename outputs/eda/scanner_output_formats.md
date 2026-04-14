# Scanner Output Format Survey — Phase 1 EDA

## Installation Summary

| Scanner | Package | Version | Install Status | Install Command |
|---------|---------|---------|----------------|-----------------|
| AgentSeal | agentseal | 0.9.6 | SUCCESS | `pip install agentseal` |
| Cisco MCP Scanner | cisco-ai-mcp-scanner | 4.6.0 | SUCCESS | `pip install cisco-ai-mcp-scanner` |
| MEDUSA | medusa-security | 2026.4.0 | SUCCESS | `pip install medusa-security` |
| Sigil | @nomarj/sigil | (npm) | SUCCESS | `npm install -g @nomarj/sigil` |
| Ant Group MCPScan | mcpscan | 0.1.0 | PARTIAL — requires DEEPSEEK_API_KEY | `pip install -e .` from GitHub clone |

**Result: 4 of 5 scanners operational without API keys. MCPScan requires DeepSeek LLM API key.**

## Scanner Architecture Types

| Scanner | Architecture | Input Mode | Requires Running Server | Deterministic |
|---------|-------------|-----------|------------------------|---------------|
| AgentSeal | Multi-agent (Strategist+Attacker+Evaluator) + tool analysis | MCP stdio connection or config | Yes (connects to running MCP server) | No (LLM-based) |
| Cisco MCP Scanner | YARA rules + LLM-as-judge + API analyzer + behavioral | Static JSON (tools/prompts/resources) or running server | No (static mode available) | Partially (YARA=yes, LLM=no) |
| MEDUSA | 76 static analyzers with pattern rules | Directory/file scanning | No | Yes (rule-based) |
| Sigil | 6-phase static analysis pipeline | Package audit (pip/npm/git) | No | Yes (rule-based) |
| MCPScan (Ant Group) | LLM-based (DeepSeek) + Semgrep rules | CLI | Requires LLM API | No (LLM-based) |

## Output Formats

### AgentSeal (scan-mcp)
- **Output format:** JSON
- **Key fields:** `servers_scanned`, `servers_connected`, `servers_failed`, `total_tools`, `runtime_results[]`, `trust_scores[]`, `summary.total_findings/critical/high/medium`, `connection_errors[]`
- **Severity levels:** Critical, High, Medium (numeric trust score 0-100)
- **Category labels:** Tool-level findings with trust scores
- **Notes:** Requires running MCP server connection. Cannot scan static files directly. The `--command` flag starts a server process. Scan failed on our minimal test server (stdout closed unexpectedly) — requires proper MCP protocol implementation.

### Cisco MCP Scanner (mcp-scanner)
- **Output format:** JSON (raw mode) or formatted text (summary/by_severity/by_tool/by_analyzer/table)
- **Key fields per tool:** `status`, `is_safe` (boolean), `findings.{analyzer}.severity`, `findings.{analyzer}.threat_names[]`, `findings.{analyzer}.threat_summary`, `findings.{analyzer}.total_findings`, `findings.{analyzer}.mcp_taxonomies[]`, `tool_name`, `tool_description`, `item_type`
- **Severity levels:** SAFE, LOW, MEDIUM, HIGH, UNKNOWN
- **Category labels:** YARA rule categories (command_injection, credential_harvesting, code_execution, data_exfiltration, tool_poisoning, prompt_injection, sql_injection, script_injection, system_manipulation, coercive_injection)
- **Taxonomy mapping:** Cisco's own MCP taxonomy (AITech-X.Y / AISubtech-X.Y.Z format)
- **Notes:** Static mode works without running server. YARA analyzer works offline. LLM and API analyzers require keys. Best-suited for our methodology.

### MEDUSA
- **Output format:** JSON + HTML reports
- **Key fields per finding:** `scanner`, `file`, `line`, `severity`, `confidence`, `issue`, `cwe` (often null), `code`, `fp_analysis.is_likely_fp/confidence/reason`
- **Severity levels:** CRITICAL, HIGH, MEDIUM, LOW, UNDEFINED
- **Confidence levels:** HIGH, MEDIUM, LOW
- **Scanner types (14 used on Python):** ToolCallbackScanner, ModelAttackScanner, MultiAgentScanner, ExcessiveAgencyScanner, AgentPlanningScanner, AgentReflectionScanner, HyperparameterScanner, LLMGuardScanner, LLMOpsScanner, PluginSecurityScanner, PostQuantumScanner, PromptLeakageScanner, SteganographyScanner, VectorDBScanner
- **Notes:** Scans source code, not tool definitions. Requires directory input. Found 31 issues on 2-file test (13 HIGH, 14 MEDIUM, 3 LOW). Flagged SAFE server with same number of generic findings as vulnerable server (false positive concern).

### Sigil
- **Output format:** Text report (6-phase analysis)
- **Phases:** (1) Install Hook Analysis, (2) Code Pattern Analysis, (3) Network & Exfiltration, (4) Credential & Secret Access, (5) Obfuscation Detection, (6) Provenance & Metadata
- **Verdict levels:** PASS, WARN, FAIL per phase
- **Notes:** Package-level supply chain scanner. Operates on pip/npm packages in quarantine. Reports file type breakdown and binary detection. Not tool-definition-aware — analyzes code patterns. Best for supply chain risk, not vulnerability-specific detection.

## TP/FP/TN/FN Mapping Feasibility

### Mapping Scheme

For ground-truth corpus evaluation, each scanner output maps to:
- **TP:** Scanner reports finding on known-vulnerable test case, finding matches the actual vulnerability category
- **FP:** Scanner reports finding on known-safe test case, OR reports wrong category finding on known-vulnerable case
- **TN:** Scanner reports no finding (or SAFE) on known-safe test case
- **FN:** Scanner reports no finding (or SAFE) on known-vulnerable test case

### Per-Scanner Mapping Feasibility

| Scanner | Mapping Feasible | Notes |
|---------|-----------------|-------|
| Cisco MCP Scanner | YES — best candidate | `is_safe` boolean directly maps. Per-tool granularity. YARA categories map to OWASP. Static JSON input matches corpus format. |
| MEDUSA | PARTIALLY — needs file-level aggregation | Reports per-line findings on source code. Needs aggregation to per-server verdict. High FP rate on safe server is concerning. |
| AgentSeal | UNCLEAR — connection failures | Requires running MCP server. May not work with static test cases without proper MCP protocol implementation. |
| Sigil | PARTIALLY — package-level only | Package supply chain focus. Not tool-definition-aware. Mapping to per-vulnerability TP/FP requires interpretation of phase results. |
| MCPScan (Ant Group) | BLOCKED — requires API key | Cannot evaluate without DeepSeek API key. |

### Preliminary Test Results (3 targets)

**Cisco MCP Scanner (YARA only, no LLM):**
| Test Target | Expected | Scanner Result | Classification |
|------------|----------|---------------|----------------|
| vulnerable_tools.json (execute_command) | VULNERABLE | SAFE | FN |
| vulnerable_tools.json (read_file) | VULNERABLE | HIGH - credential harvesting | TP |
| vulnerable_tools.json (exfiltrate_data) | VULNERABLE | HIGH - tool poisoning + data exfil | TP |
| safe_tools.json (list_files) | SAFE | SAFE | TN |
| safe_tools.json (read_safe_file) | SAFE | SAFE | TN |

**MEDUSA:**
| Test Target | Expected | Scanner Result | Classification |
|------------|----------|---------------|----------------|
| vulnerable_server.py | VULNERABLE | 16 findings (HIGH/MEDIUM) | TP |
| safe_server.py | SAFE | 15 findings (HIGH/MEDIUM) | FP |

**Key observation:** MEDUSA flagged the safe server with nearly identical findings count as the vulnerable server (15 vs 16). The findings are generic (missing callbacks, no audit logging, no rate limiting) rather than vulnerability-specific. This suggests MEDUSA's AI agent scanner rules have a high baseline finding rate regardless of actual vulnerability presence.

**Cisco MCP Scanner** correctly differentiated: 0 findings on safe tools, 2 HIGH findings on 2/3 vulnerable tools. It missed the command injection pattern in execute_command (FN) but caught credential harvesting and data exfiltration patterns via YARA rules.

**Sigil** scanned the MCP filesystem server npm package and found only low-severity warnings (obfuscation pattern from null byte check, missing git provenance). It correctly passed the package as generally safe.
