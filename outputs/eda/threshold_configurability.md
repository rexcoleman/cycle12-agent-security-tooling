# Scanner Threshold Configurability — Phase 1 EDA (Task 4)

## Summary

**Key finding: Multiple scanners have configurable thresholds, enabling OC curve construction.**

## Per-Scanner Threshold Analysis

### Cisco MCP Scanner (cisco-ai-mcp-scanner v4.6.0)

**Configurable: YES — multiple dimensions**

1. **Severity filter:** `--severity-filter {all,high,unknown,medium,low,safe}` — filters results by severity level. This directly controls the operating point: filtering at "high" produces fewer findings (higher precision, lower recall) vs "all" (lower precision, higher recall).

2. **Analyzer selection:** `--analyzers` flag accepts comma-separated list of: `api,yara,llm,behavioral,virustotal`. Running with only YARA rules vs YARA+LLM vs all analyzers produces different detection profiles.

3. **Tool-level granularity:** `--tool-filter` for pattern matching on tool names.

**Operating points for OC curves:**
- Point 1 (High sensitivity): All analyzers, severity-filter=all
- Point 2 (Medium sensitivity): YARA only, severity-filter=all  
- Point 3 (Low sensitivity / high precision): YARA only, severity-filter=high
- Point 4 (Maximum): All analyzers + LLM, severity-filter=all (requires API key)

### AgentSeal (v0.9.6)

**Configurable: YES — trust score threshold**

1. **Min-score threshold:** `--min-score MIN_SCORE` — sets trust score threshold (0-100). Servers scoring below this threshold trigger exit code 1. The trust score is computed per-server.

2. **Deep analysis toggle:** `--deep` flag enables "Deep analysis with LLM verification (Pro)" — adds another detection layer.

**Operating points for OC curves:**
- Point 1: --min-score 90 (strict, few pass)
- Point 2: --min-score 70 (default/moderate)
- Point 3: --min-score 50 (lenient)
- Point 4: --deep mode (adds LLM verification)

**Caveat:** AgentSeal requires running MCP server connection. Static test case scanning not directly supported. Operating points may only be usable if MCP servers can be properly stood up from corpus.

### MEDUSA (v2026.4.0)

**Configurable: YES — severity threshold for pass/fail**

1. **Fail-on threshold:** `--fail-on {critical|high|medium|low}` — sets the severity level at which scan returns exit code 1.

2. **Scanner selection:** `medusa scanners` lists all 76 scanners. Individual scanner override via `medusa override`. Can enable/disable specific scanner categories.

3. **Quick mode:** `--quick` only scans changed files (relevant for incremental analysis).

**Operating points for OC curves:**
- Point 1: --fail-on low (catches everything)
- Point 2: --fail-on medium (moderate sensitivity)
- Point 3: --fail-on high (only high/critical findings)
- Point 4: --fail-on critical (only critical findings)

**Caveat:** MEDUSA scans source code, not tool definitions. The --fail-on threshold affects binary pass/fail but doesn't change what findings are reported — it only changes the exit code. For OC curves, we need to filter the JSON findings by severity post-hoc.

### Sigil

**Configurable: LIMITED — binary pass/fail per phase**

1. **6 analysis phases** each produce PASS/WARN/FAIL independently.
2. **--pro flag** for AI-powered analysis (requires account).
3. No severity threshold configuration. No numeric score.

**Operating points:** Only 2 meaningful points:
- Standard analysis (6 phases, rule-based)
- Pro analysis (adds AI layer, requires account)

**Assessment:** Insufficient for OC curve construction. Binary scanner with limited configurability.

### MCPScan (Ant Group, v0.1.0)

**BLOCKED — requires DEEPSEEK_API_KEY**

Could not assess threshold configurability. Based on code inspection (imports semgrep + OpenAI client), likely uses LLM-as-judge with possible prompt-level sensitivity control, but unverifiable without API key.

## Threshold Configurability Summary

| Scanner | Configurable? | Mechanism | # Operating Points | OC Curve Feasible? |
|---------|--------------|-----------|-------------------|--------------------|
| Cisco MCP Scanner | YES | Severity filter + analyzer selection | 4+ | YES |
| AgentSeal | YES | Trust score threshold + deep mode | 4 | CONDITIONAL (needs running server) |
| MEDUSA | YES | Fail-on severity threshold | 4 | YES (post-hoc filtering) |
| Sigil | LIMITED | Standard vs Pro mode only | 2 | NO (insufficient points) |
| MCPScan | UNKNOWN | Blocked by API key requirement | Unknown | UNKNOWN |

## Implications for Methodology

**Full OC curves are feasible** for at least 2 scanners (Cisco MCP Scanner and MEDUSA) with 4+ operating points each. AgentSeal adds a 3rd if MCP server connectivity is resolved.

This means the **threshold kill condition is NOT triggered**. The methodology can proceed with full OC curve construction rather than falling back to Youden-only comparison.

**Recommendation for Statistical Plan:** Since configurable thresholds exist and OC curves are constructible, the Kolmogorov-Smirnov test should be added to the statistical analysis plan for comparing OC curve shapes between scanners. K-S test was specified in ED section 0 criterion 5 (falsification) but is missing from the Statistical Plan table. This is documented as a deviation in EXECUTION_PROTOCOL.md section 5.
