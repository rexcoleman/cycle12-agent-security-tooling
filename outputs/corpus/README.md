# Agent Security Scanner Ground-Truth Corpus

## Overview

A ground-truth corpus of MCP (Model Context Protocol) servers for evaluating
agent security scanner detection effectiveness. Contains 25 known-vulnerable
and 12 known-safe servers across 5 OWASP Agentic AI categories.

## Taxonomy Mapping

| OWASP Category | ID | Vulnerable Cases | Description |
|---|---|---|---|
| Agent Goal Hijack | ASI01 | 3 | Tool poisoning, tool shadowing, indirect prompt injection |
| Tool Misuse | ASI02 | 3 | Path traversal, argument injection |
| Identity and Privilege Abuse | ASI03 | 3 | Missing authentication, authorization bypass, DNS rebinding |
| Agentic Supply Chain | ASI04 | 6 | SSRF, schema inconsistency, name squatting, configuration drift |
| Unexpected Code Execution | ASI05 | 10 | Command injection, eval/exec injection |

## Construction Methodology

### Sources

1. **CVE-based test cases** (17 cases): Derived from real CVEs published Jan-Apr 2026
   affecting MCP servers. Each CVE mapped to specific CWE and OWASP ASI category.
   
2. **MCPSecBench supplementation** (8 cases): Derived from AIS2Lab MCPSecBench
   attack taxonomy. Used for categories with insufficient CVE coverage (ASI01, ASI04).
   
3. **Safe control cases** (12 cases): 7 patched variants of vulnerable cases
   plus 5 complex-but-safe decoy servers to test false positive rates.

### Server Implementation

All servers use the `mcp` Python SDK with `FastMCP` and stdio transport:
- Implement full MCP protocol (initialize/initialized handshake, tools/list)
- Self-contained, no external service dependencies
- Include both `server.py` (runnable) and `tools.json` (static scanning)

### Labeling Validation

- 24% stratified sample (9 of 37 cases) independently re-labeled
- Cohen's kappa: 1.0 (perfect agreement)
- Methodology: Automated code analysis for vulnerability indicators
  (eval, os.system, shell=True, path traversal, missing auth, tool poisoning patterns)
  cross-checked against safety indicators (input validation, allowlists, auth checks)

## Directory Structure

```
outputs/corpus/
  manifest.csv                          # Complete corpus manifest
  labeling_validation.md               # Inter-rater agreement report
  README.md                            # This file
  vulnerable/
    {test_case_id}/
      server.py                        # Runnable MCP server
      tools.json                       # Tool definitions for static scanning
      manifest.json                    # Metadata and ground truth label
  safe/
    {test_case_id}/
      server.py
      tools.json
      manifest.json
```

## Usage: Running Scanners Against Corpus

### Prerequisites

On Mac Mini with scanner venvs at `~/scanners/`:
```bash
# Corpus server venv (for running MCP servers)
source ~/scanners/corpus_env/bin/activate
```

### Cisco MCP Scanner

```bash
# Static mode (tools.json)
source ~/scanners/cisco_env/bin/activate
mcp-scanner --format raw --analyzers yara static \
  --tools outputs/corpus/vulnerable/{case_id}/tools.json

# Stdio mode (running server)
mcp-scanner --format raw --analyzers yara stdio \
  --stdio-command ~/scanners/corpus_env/bin/python3 \
  --stdio-arg outputs/corpus/vulnerable/{case_id}/server.py
```

### AgentSeal

```bash
source ~/scanners/agentseal_env/bin/activate
agentseal scan-mcp --command \
  '/full/path/to/corpus_env/bin/python3 /full/path/to/corpus/{case_id}/server.py'
```

Note: AgentSeal free version connects and enumerates tools but requires
Pro license for toxic flow analysis and trust scoring.

### MEDUSA

```bash
source ~/scanners/medusa_env/bin/activate
echo 'yes' | medusa scan outputs/corpus/vulnerable/{case_id} --format json
# Reports saved to ~/.medusa/reports/
```

### Sigil

```bash
/opt/homebrew/lib/node_modules/@nomarj/sigil/bin/sigil scan \
  outputs/corpus/vulnerable/{case_id}
```

## Known Limitations

1. **CVE fidelity**: Test cases are minimal reproductions, not exact replicas
   of the original vulnerable software. They capture the vulnerability pattern
   (e.g., unsanitized input to subprocess.run with shell=True) but not the
   full application context.

2. **Semantic vulnerabilities**: ASI01 cases (tool poisoning, shadowing) and
   some ASI04 cases (name squatting, schema inconsistency) involve semantic
   rather than code-level vulnerabilities. Static code scanners may not detect
   these by design.

3. **Scanner coverage gap**: Cisco YARA rules scan tool descriptions, not
   source code. Tools with legitimate descriptions but vulnerable implementations
   will not be detected by YARA alone.

4. **AgentSeal Pro paywall**: Toxic flow analysis and trust scoring require
   Pro license. Free version only connects and enumerates tools.

5. **MEDUSA generic findings**: Some MEDUSA scanners (ModelAttackScanner)
   produce findings on both vulnerable and safe servers, inflating FP counts
   unless filtered to vulnerability-specific scanners.

6. **No runtime interaction tests**: All test cases are designed for static
   or tool-definition-level scanning. Runtime behavioral vulnerabilities
   (prompt injection, confused deputy) require LLM interaction to fully test.
