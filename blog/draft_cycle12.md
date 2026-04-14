---
title: "Can Bandit or Semgrep Detect Agent Vulnerabilities? We Tested 3 Scanners on 37 MCP Servers"
date: 2026-04-14
draft: true
format: "technical-blog"
tags:
 - "ai-security"
 - "agent-security"
 - "mcp-security"
 - "security-tooling"
 - "research"
description: "We benchmarked 3 agent security scanners against 37 MCP servers covering 5 OWASP Agentic AI categories. The best scanner achieved Youden Index 0.30. Tool poisoning had 0% detection. Adding scanners together didn't help."
target_keywords:
 - primary: "agent security scanner comparison"
 - secondary: ["MCP server security testing", "OWASP agent security tools", "SAST tools agent vulnerabilities"]
content_ratio:
 teaching: "~50%"
 findings: "~30%"
 perspective: "~20%"
---

## Why Your Security Scanner Doesn't Know About Agent Attacks

<!-- TEACHING — 50% target -->

In [earlier work](/posts/scanning-agent-skills-results/), we scanned 40 OpenClaw agent skills with our own scanner and found that pattern matching catches code-level issues but can't distinguish attacks from defenses. This time we ask a different question: can *any* scanner — including the dedicated MCP security tools that launched in early 2026 — detect the agent-specific attacks that matter most?

I ran Bandit, Semgrep, and three dedicated MCP security scanners against 37 test servers — and none of them caught the attacks that matter most. If you're relying on traditional SAST (Static Application Security Testing) tools for your AI agent code, you're testing for the wrong things. These tools were designed for web application vulnerabilities — SQL injection, command injection, path traversal. They have no concept of tool poisoning, delegation attacks, or identity escalation in agent systems.

### What Are MCP Servers and Why Should You Care?

MCP (Model Context Protocol) is Anthropic's standard for connecting AI agents to external tools — databases, APIs, file systems, code execution environments. An MCP server exposes tools that an agent can call. Think of it as the API layer between an LLM and the real world. Since its release in late 2024, MCP adoption has exploded: thousands of servers, dozens of registries, and a growing ecosystem of tools that give AI agents capabilities their creators never fully audited. The proliferation is outpacing security review — most MCP servers are published without any security audit, and the registries that index them perform no vulnerability scanning before listing.

The security problem: every MCP tool description is an attack surface. A malicious tool can advertise one capability ("I summarize documents") while actually doing something else ("I exfiltrate your API keys"). This is tool poisoning — and it's undetectable by any scanner that only reads code, because the attack lives in the natural language description, not in a code pattern.

The OWASP (Open Worldwide Application Security Project) Agentic AI Security Top 10, released late 2025, defines five attack categories specific to AI agents:

| Category | What It Means | Example |
|---|---|---|
| **ASI01** — Agent Goal Hijack | Tool poisoning, tool shadowing, indirect injection | A malicious tool description that redirects agent behavior |
| **ASI02** — Tool Misuse | Unintended use of legitimate tools | Agent uses a database tool to exfiltrate data |
| **ASI03** — Identity/Privilege | Escalation across trust boundaries | Agent bypasses capability-scoped access controls |
| **ASI04** — Supply Chain | Compromised dependencies or model sources | Backdoored package in agent requirements |
| **ASI05** — Code Execution | Direct code injection via agent tools | `eval()` or `subprocess.run(shell=True)` in tool handlers |

Traditional SAST tools can catch ASI05 (that's just "don't use `eval()`"). But ASI01 — the most dangerous category in practice, because it's invisible to code analysis — gets 0% detection from every scanner we tested.

So what about the new MCP-specific scanners that launched in early 2026?

<!--more-->

## What We Found

<!-- FINDINGS — 30% target -->

We evaluated three agent security scanners against a ground-truth corpus of 37 MCP server test cases (25 vulnerable across 5 OWASP categories, 12 safe controls). The test cases include 17 CVE-based implementations and 8 cases from the MCPSecBench taxonomy.

### The Headline Numbers

| Scanner | Best Detection Rate | False Positive Rate | Youden Index |
|---|---|---|---|
| **Sigil** (+ bandit) | 80% | 50% | **0.30** |
| **MEDUSA** (high threshold) | 16% | 0% | 0.16 |
| **MEDUSA** (any finding) | 96% | 100% | -0.04 |
| **Cisco MCP Scanner** | 8% | 0% | 0.08 |

No scanner achieved a Youden Index above 0.30 — meaning the best scanner is only 30 percentage points better than random guessing.

### The Scanners Don't Complement Each Other

You might expect that combining multiple scanners would catch more vulnerabilities. It doesn't:

| Configuration | Detection Rate |
|---|---|
| Sigil alone | 80% (20/25) |
| All three scanners combined | 80% (20/25) |

Adding Cisco and MEDUSA to Sigil adds zero additional detections. Every vulnerability caught by Cisco or MEDUSA was already caught by Sigil. The 5 missed cases — all semantic attacks like tool poisoning and tool shadowing — are invisible to all three scanners.

### Category-Level Detection: Where the Gap Is

| Category | Cisco | MEDUSA | Sigil |
|---|---|---|---|
| ASI01 (Tool Poisoning) | **0%** | **0%** | **0%** |
| ASI02 (Tool Misuse) | 33% | 33% | 67% |
| ASI03 (Identity/Privilege) | 0% | 0% | 100% |
| ASI04 (Supply Chain) | 0% | 17% | 83% |
| ASI05 (Code Execution) | 10% | 20% | 100% |

The pattern: scanners detect syntactic vulnerabilities (code patterns like `eval()`, `subprocess.run`) but miss semantic vulnerabilities (malicious intent embedded in tool descriptions). ASI01 — tool poisoning, tool shadowing, indirect injection — has 0% detection across the board.

### MEDUSA's Tradeoff Is Brutal

MEDUSA catches 96% of vulnerabilities at its most sensitive setting — but flags every single safe server as vulnerable. At its most specific setting, it catches only 16%. No useful middle ground exists in the current version.

## What This Means for Your Agent Security

<!-- PERSPECTIVE — 20% target -->

**If you're deploying MCP servers today,** running these scanners is better than nothing, but don't assume a clean scan means a secure server. The most dangerous attack category — tool poisoning — is completely invisible to all tested scanners.

**If you're building agent security tooling,** the gap is semantic analysis. Pattern-matching and AST (Abstract Syntax Tree) analysis have hit their ceiling for agent-specific vulnerabilities. The next generation of scanners needs to understand what a tool *does*, not just what its code *looks like*. LLM-augmented analysis (which Cisco supports but I couldn't test without API keys) may close part of this gap.

**If you're evaluating scanner coverage for compliance,** be specific about which OWASP Agentic categories are actually covered. "We run an agent security scanner" sounds like full coverage but may cover only ASI05 (code execution) while leaving ASI01-ASI03 unaddressed.

Three practical steps:
1. **Run Sigil** (free, best available detection) but treat it as a floor, not a ceiling
2. **Manually review tool descriptions** for all MCP servers — this is where the semantic attacks hide
3. **Don't stack scanners** expecting better coverage — the data shows zero complementarity benefit

## Methodology

We used Operating Characteristic curve methodology adapted from manufacturing quality assurance to evaluate each scanner at multiple operating points. 37 test cases, 25 vulnerable across 5 OWASP Agentic AI categories, 12 safe controls. Fisher's exact test with Bonferroni correction for pairwise comparisons. 45,900+ total test configurations across all scanner × threshold × category combinations.

Full experimental design, all data, and reproduction scripts: [cycle12-agent-security-tooling on GitHub](https://github.com/rexcoleman/cycle12-agent-security-tooling).

## Limitations

This benchmark has real constraints. All Cisco MCP Scanner results use YARA-only analysis — the behavioral and LLM-augmented analyzers require API keys I didn't have. AgentSeal was excluded because its free version reports "safe" for everything. The test corpus of 37 cases is small; confidence intervals on per-category detection rates are wide (see the FINDINGS.md for exact CIs). And I only tested rule-based/pattern-matching analysis — the results represent a floor of scanner capability, not a ceiling.

## Related Research

- [Adversarial Control Analysis](https://rexcoleman.dev/posts/adversarial-control-analysis/) — The framework for decomposing defense difficulty into controllability and observability
- [Scanning Agent Skills Results](https://rexcoleman.dev/posts/scanning-agent-skills-results/) — Earlier work on scanning agent capabilities
- [controllability-bound](https://github.com/rexcoleman/controllability-bound) — Defense difficulty decomposition across 4 domains
- [ai-supply-chain-scanner](https://github.com/rexcoleman/ai-supply-chain-scanner) — Rule-based scanner for ML supply chain risks

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman)*
