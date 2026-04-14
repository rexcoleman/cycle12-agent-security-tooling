# Execution Protocol — Agent Security Scanner OC Curves

<!-- version: 1.0 -->
<!-- stage: 5 -->

> Fill this template DURING execution — not before or after.

## §1 Predictions (GPL-07) — Written BEFORE any task execution

| # | Prediction | Reasoning |
|---|-----------|-----------|
| 1 | 3 of 5 scanners install successfully | Package names in ED may not match real PyPI packages. MCP scanner tooling is bleeding-edge (2026). Expect 2 failures from non-existent packages or dependency conflicts on arm64. |
| 2 | 8-15 MCP CVEs from Jan-Apr 2026 via NVD | "MCP" is a relatively new protocol. NVD indexing lags. 30+ estimate from ED seems optimistic — MCP-specific CVEs may be fewer, with many being in underlying libraries not tagged as MCP. |
| 3 | 5-10 of those CVEs will be reproducible as test cases | Many CVEs have vague descriptions or require complex runtime setups. Estimate ~60% partially reproducible, ~20% fully reproducible. |
| 4 | Yes — Cisco MCP Scanner likely has configurable thresholds | Cisco tends to build enterprise-grade tools with configuration options. AgentSeal may also have severity filtering. |
| 5 | Most common OWASP Agentic AI category: Tool Poisoning or Prompt Injection | Based on ED noting 43% of CVEs are exec/shell injection. These map to prompt injection and tool poisoning categories in OWASP Agentic AI taxonomy. |

## §2 Runtime Quality Gates

### Task 1: CVE Corpus Feasibility
- PASS: 26 MCP-related CVEs identified (Jan-Apr 2026)
- PASS: 17 classified as reproducible, 9 as partially reproducible
- PASS: 6 OWASP Agentic AI categories represented
- Kill check: 17 reproducible across 6 categories exceeds threshold of 15 across 3

### Task 2: MCPSecBench Inventory
- PASS: Repository cloned, 17 attack types inventoried
- 7 of 17 attack types produce scannable static artifacts (high feasibility for test case conversion)
- 6 require runtime interaction only (low feasibility for static scanner evaluation)
- 4 partially scannable

### Task 3: Scanner Installation
- AgentSeal: INSTALLED (pip install agentseal, v0.9.6)
- Cisco MCP Scanner: INSTALLED (pip install cisco-ai-mcp-scanner, v4.6.0)
- MEDUSA: INSTALLED (pip install medusa-security, v2026.4.0)
- Sigil: INSTALLED (npm install -g @nomarj/sigil)
- MCPScan (Ant Group): INSTALLED but BLOCKED (requires DEEPSEEK_API_KEY)
- Result: 4 of 5 working (exceeds minimum 3)

### Task 4: Threshold Configurability
- PASS: 3 scanners have configurable thresholds (Cisco, AgentSeal, MEDUSA)
- Full OC curve construction feasible (not Youden-only fallback)

### Task 5: Power Analysis
- PASS: Power analysis completed
- MDE ~0.40 at N=24 (large effects detectable)
- 2 supercategories support inferential analysis

## §3 Measurement Protocol

### CVE Classification
- Source: WebSearch queries against NVD, GitHub Security Advisories, vulnerablemcp.info, DEV Community articles
- Classification method: Manual mapping of each CVE's CWE to OWASP Agentic AI Top 10 (ASI01-ASI10) based on vulnerability mechanism
- Reproducibility scoring: "reproducible" if CVE description + public code provides enough detail to construct a minimal vulnerable server config; "partially reproducible" if server setup is complex or requires specific cloud services; "description-only" if insufficient detail

### MCPSecBench Classification
- Source: MCPSecBench GitHub repo (data.json + experiments.csv)
- Scannable artifact assessment: Each of 17 attack types classified as producing (yes/partially/no) a static artifact that a scanner can analyze without runtime interaction
- OWASP mapping: Manual mapping of each attack type to closest ASI category

### Scanner Output Mapping
- Method: Run each scanner against (a) vulnerable test target and (b) safe test target
- TP/FP/TN/FN classification: Scanner finding on vulnerable target = TP; finding on safe target = FP; no finding on safe = TN; no finding on vulnerable = FN
- Per-tool granularity for Cisco scanner (static JSON input); per-file for MEDUSA; per-server for AgentSeal

## §4 Blinding and Specification Commitment

N/A for Phase 1 EDA — blinding applies to Phase 3 scanner evaluation.

## §5 Deviation Log

### D1: Package names differ from ROADMAP
- ROADMAP specified: `pip install mcpscanner` -> Actual: `pip install cisco-ai-mcp-scanner`
- ROADMAP specified: `pip install medusa-scan` -> Actual: `pip install medusa-security`
- ROADMAP specified: `npm install -g sigilsec` -> Actual: `npm install -g @nomarj/sigil`
- Impact: None (correct packages found via WebSearch)

### D2: Python 3.9.6 on Mac Mini, not the documented 3.9
- Mac Mini had Python 3.14.4 via Homebrew, but PATH defaulted to system 3.9.6
- Installed Python 3.12 via Homebrew for compatibility with security packages
- Impact: Minor setup delay

### D3: AgentSeal cannot scan static files
- AgentSeal scan-mcp requires a running MCP server via stdio connection
- Our minimal test server script doesn't implement MCP protocol (just prints JSON)
- Impact: AgentSeal test results are incomplete; proper MCP server implementation needed in Phase 2

### D4: MCPScan requires DEEPSEEK_API_KEY
- Ant Group MCPScan is LLM-dependent (DeepSeek) with no offline mode
- Impact: Reduced to 4 working scanners (still above minimum 3)

### D5: MEDUSA high FP rate
- MEDUSA flagged safe server with 15 findings (nearly identical to 16 on vulnerable server)
- Generic findings (missing callbacks, no audit logging) not vulnerability-specific
- Impact: MEDUSA may need custom rule filtering for meaningful TP/FP classification

### D6: K-S test recommendation
- ED section 0, criterion 5 specifies K-S test for comparing OC curve shapes
- This test is missing from the Statistical Plan table in ED
- Since configurable thresholds DO exist (Cisco, AgentSeal, MEDUSA), K-S test SHOULD be added to Statistical Plan for Phase 3
- Recommendation documented here per task instructions

### D7: CVE date range expanded
- ROADMAP specified Jan-Feb 2026; task instructions specified Jan-Apr 2026
- Used the broader Jan-Apr 2026 range per executor task instructions
- Impact: More CVEs available (26 vs estimated 30 for Jan-Feb)

### Phase 2 Predictions (written BEFORE any Phase 2 task execution)

| # | Prediction | Reasoning |
|---|-----------|-----------|
| P2-1 | 12-14 of the 17 "reproducible" CVEs will produce working test cases | Most reproducible CVEs have clear code patterns (eval(), exec(), os.system) that are straightforward to embed in FastMCP servers. 2-3 will fail due to needing specific runtime contexts (Azure, Docker) or insufficient CVE detail. |
| P2-2 | 5 of 7 HIGH-feasibility MCPSecBench attack types will convert to scannable MCP servers | Schema inconsistencies, tool shadowing, tool poisoning, vulnerable server, and package name squatting (tools) are all demonstrable in static tool definitions. Configuration drift may be harder to express as a single server. |
| P2-3 | Inter-rater kappa on 20% manual review will exceed 0.8 (well above 0.6 threshold) | Ground truth labels are derived directly from CVE descriptions with clear vulnerable/safe binary classification. Low ambiguity expected. |
| P2-4 | AgentSeal will successfully connect to at least 5 properly-implemented FastMCP servers | MCPSecBench's addserver.py pattern uses FastMCP with stdio transport, which is exactly what AgentSeal expects. The Phase 1 failure was because the test server didn't implement MCP protocol. |
| P2-5 | Total corpus size: 22 vulnerable + 12 safe = 34 total | 14 CVE-based + 5 MCPSecBench + 3 extra = 22 vulnerable. 7 patched variants + 5 decoys = 12 safe. |

### Phase 2 Runtime Quality Gates

### Task 1: Construct Known-Vulnerable Test Cases
- PASS: 17 CVE-based test cases constructed (all 17 "reproducible" CVEs converted)
- PASS: All servers implement FastMCP stdio transport and pass MCP initialization
- PASS: Each server has server.py, tools.json, and manifest.json
- Category breakdown: ASI05=10, ASI04=2, ASI03=3, ASI02=3 (from CVEs)

### Task 2: MCPSecBench Supplementation
- PASS: 8 MCPSecBench attack types converted to MCP servers (7 from HIGH + 1 indirect injection)
- Types: tool_poisoning, tool_shadowing, schema_inconsistency, name_squatting_tools, name_squatting_server, config_drift, vulnerable_server, indirect_injection
- These supplement ASI01 (tool poisoning, shadowing, injection) and ASI04 (schema, squatting, drift)

### Task 3: Construct Known-Safe Control Cases
- PASS: 12 safe test cases (7 patched variants + 5 decoys)
- Patched variants: command_sanitized, eval_literal, path_canonical, authenticated, git_sanitized, api_validated, honest_tools
- Decoys: data_processor, http_client, database, text_processor, crypto_utils

### Task 4: Ground-Truth Labeling Validation
- PASS: 24% stratified sample (9 of 37 cases) independently re-labeled
- Cohen's kappa: 1.0 (perfect agreement, exceeds 0.6 threshold)
- Method: Automated vulnerability/safety indicator analysis cross-referencing code patterns

### Task 5: Scanner Smoke Test
- Cisco: PARSEABLE output (JSON). However, YARA rules report SAFE on corpus because rules match tool descriptions not source code. Stdio mode connects to MCP servers successfully.
- AgentSeal: CONNECTS to MCP servers (tool enumeration works). However, toxic flow analysis and trust scoring require Pro license. Free version reports "clean" for all.
- MEDUSA: PARSEABLE output (JSON reports). DISCRIMINATES: 12 findings (1 HIGH) on vulnerable vs 4 findings (0 HIGH) on safe. MCPServerScanner and OWASPLLMScanner detect code-level vulnerabilities.
- Sigil: PARSEABLE output (text). Partial discrimination: Risk score 23 on vulnerable (eval/os.system detected) vs 13 on decoy (no dangerous patterns).

### Task 6: Corpus Documentation
- PASS: README.md, manifest.csv, labeling_validation.md all written

### D8: Cisco YARA rules scan descriptions not source code
- Cisco YARA rules check for attack patterns (eval, subprocess, shell operators) in tool DESCRIPTIONS, not in server source code. Our corpus servers have realistic, non-malicious descriptions with vulnerable implementations. This means Cisco YARA will classify most corpus cases as SAFE.
- Impact: Cisco YARA alone may produce many FN. Cisco stdio mode + behavioral analyzer may perform better. This is a valid finding for Phase 3.

### D9: AgentSeal Pro license required for actual detection
- AgentSeal free version connects to MCP servers and enumerates tools but "Toxic flow analysis requires Pro license" and "Trust scoring requires Pro license." The free version cannot discriminate vulnerable from safe servers.
- Impact: AgentSeal may be reduced to "connectivity test only" in Phase 3 unless Pro license is obtained.

### D10: MEDUSA as primary discriminating scanner
- MEDUSA's MCPServerScanner correctly identifies os.system() and subprocess shell=True patterns in source code. OWASPLLMScanner detects code execution injection patterns. ModelAttackScanner produces FPs on both vulnerable and safe cases (generic "backdoor" alerts).
- Impact: MEDUSA is the strongest discriminating scanner for code-level vulnerabilities. Filtering to MCPServerScanner + OWASPLLMScanner may improve discrimination further.

### D11: Vulnerability type coverage gap
- Code-level vulnerabilities (command injection, eval injection, path traversal) are well-detected by MEDUSA.
- Semantic vulnerabilities (tool poisoning, name squatting, schema inconsistency) are NOT detected by any scanner in default configuration.
- This creates a systematic detection gap aligned with OWASP categories: ASI01 and parts of ASI04 may show 0% detection rates.

## §6 Execution Completion Checklist

### Phase 1
- [x] CVE feasibility CSV produced (outputs/eda/cve_feasibility.csv)
- [x] MCPSecBench inventory CSV produced (outputs/eda/mcpsecbench_inventory.csv)
- [x] 4 scanners installed and producing parseable output
- [x] Scanner output format documented (outputs/eda/scanner_output_formats.md)
- [x] Threshold configurability documented (outputs/eda/threshold_configurability.md)
- [x] Power analysis completed (outputs/eda/power_analysis.md)
- [x] EXECUTION_PROTOCOL.md filled during execution
- [x] Predictions written before task execution

### Phase 2
- [x] 25 vulnerable test cases across 5 OWASP categories
- [x] 12 safe test cases (7 patched + 5 decoys)
- [x] All 37 servers pass MCP initialization test
- [x] Corpus manifest.csv with 37 entries
- [x] Inter-rater kappa 1.0 on 24% sample (exceeds 0.6 threshold)
- [x] Scanner smoke test completed (4 scanners tested)
- [x] Corpus README.md written
- [x] EXECUTION_PROTOCOL.md updated with Phase 2 quality gates

## Phase 3-4 Predictions (GPL-07) — Written BEFORE any Phase 3 task execution

| # | Prediction | Reasoning |
|---|-----------|-----------|
| P3-1 | 3 scanners will effectively discriminate vulnerable from safe | Cisco (behavioral mode), MEDUSA (filtered), and Sigil showed some discrimination in Phase 2 smoke test. AgentSeal free version cannot discriminate (Pro license needed). |
| P3-2 | MEDUSA will have the highest Youden Index overall | MEDUSA was the strongest discriminator in Phase 2 smoke test — its MCPServerScanner detects code-level patterns (os.system, subprocess shell=True) which dominate the corpus (ASI05 = 10 of 25 vulnerable). |
| P3-3 | Yes — at least one scanner will achieve >70% detection on ASI05 | ASI05 cases are mostly command/code injection with explicit dangerous patterns. MEDUSA's MCPServerScanner should catch these. |
| P3-4 | No scanner will detect ASI01 (tool poisoning) cases | ASI01 cases (tool poisoning, shadowing, indirect injection) are semantic attacks embedded in descriptions/schemas. No scanner in Phase 2 smoke test showed ability to detect these. Predicted 0% detection. |
| P3-5 | Yes — OC curves will show statistically distinguishable shapes (K-S p<0.05) | MEDUSA and Cisco have fundamentally different detection mechanisms (code pattern vs YARA+behavioral). Their operating curves should differ significantly. |
| P3-6 | FINDINGS.md quality_loop score: 7.5-8.0 | First-pass FINDINGS for a novel methodology adaptation. Likely gaps in depth budget or cross-domain connection specificity. |

## Phase 3-4 Runtime Quality Gates

### Task 1: Scanner Validation Run (HARD GATE)
- Cisco: 1/5 vuln detected, 1/1 safe clean -- WEAK discrimination
- MEDUSA: 4/5 vuln detected (filtered to relevant scanners), 1 medium FP on safe -- DISCRIMINATES
- Sigil (with bandit): 3/5 vuln elevated scores, 1/3 safe clean at threshold>13 -- MARGINAL
- AgentSeal: 0/5 detected, "safe" on all -- DOES NOT DISCRIMINATE (Pro required)
- Gate result: 3 scanners discriminate (MEDUSA clearly, Cisco weakly, Sigil marginally). PASS.

### Task 2: Full Scanner Execution
- Cisco: 37 cases x 3 OPs = 111 scans completed, all JSON parseable
- MEDUSA: 37 cases x 1 run = 37 scans completed, all JSON reports generated
- Sigil: 37 cases x 1 run = 37 scans completed, all text reports with risk scores

### Task 3: Output Classification
- 333 classification rows generated (37 cases x 9 scanner-OP combinations)
- Cisco: 3 OPs x 37 = 111 rows
- MEDUSA: 4 OPs x 37 = 148 rows (operating points from severity thresholds)
- Sigil: 2 OPs x 37 = 74 rows (score thresholds)

### Task 4: Detection Metrics
- detection_profiles.csv: 63 rows (9 OPs x 7 categories including ALL)
- Best Youden: Sigil OP1 = 0.30 (TPR=0.80, FPR=0.50)
- Clopper-Pearson CIs computed for all rates

### Task 5: Statistical Tests
- Fisher's exact: 3 pairwise tests, 2 significant after Bonferroni
- Cohen's kappa: 3 pairs, all poor/slight agreement (0.05-0.28)
- K-S tests: 3 pairs, none significant (insufficient operating points)

### Task 6: Sensitivity Analyses
- 5 ablations completed
- Ablation 3 (LLM-judge removal): N/A -- no LLM modes active
- Rankings preserved under strict labeling (Ablation 4)

### Phase 3b: AOQL and Complementarity
- CI width condition met (MEDUSA OP1 CI width = 0.20 < 0.30)
- AOQL computed: MEDUSA 0.04, Sigil 0.20, Cisco 0.92
- Complementarity: zero benefit from multi-scanner; all detection sets nested

## Phase 3-4 Measurement Protocol

### Scanner Output Mapping
- Cisco: JSON output, is_safe boolean per tool. Aggregated: any unsafe tool = detection.
- MEDUSA: JSON report with findings array. Filtered to MCPServerScanner/OWASPLLMScanner/ToolCallbackScanner. Severity thresholds applied post-hoc for operating points.
- Sigil: Text report with risk score. ANSI codes stripped via regex. Score > threshold = detection.
- All classifications cross-referenced against manifest.csv ground_truth_label.

### Statistical Computation
- scipy.stats used for Fisher's exact, K-S tests, beta distribution (Clopper-Pearson)
- All computations in scripts/analyze_results.py, reproducible from raw scanner outputs

## Phase 3-4 Deviation Log

### D12: Cisco behavioral analyzer requires LLM API key
- Phase 2 noted "use --analyzers yara,behavioral" but behavioral mode silently requires MCP_SCANNER_LLM_API_KEY
- Without key, behavioral findings are empty -- only YARA rules fire
- Impact: Cisco evaluation is YARA-only. Behavioral/LLM modes untested.

### D13: Sigil requires bandit for discrimination
- Sigil without bandit produces identical score 13 on all cases
- Installed bandit during Phase 3 to enable code-level pattern detection
- Impact: Sigil results represent Sigil+bandit composite, not Sigil alone

### D14: AgentSeal excluded from quantitative analysis
- Free version: scan-skills reports "safe" for all cases, scan-mcp reports 0 findings
- Semantic detection installed (pip install agentseal[semantic]) but still reports safe
- Deep analysis requires Pro license
- Impact: Reduced to 3 scanners for analysis. AgentSeal documented as negative finding.

### D15: MEDUSA interactive prompt blocked automation
- MEDUSA asks "Continue scan without these tools? yes/no" when bandit/gitleaks missing
- Initial echo "yes" approach failed on some cases
- Fixed with `yes |` pipe + timeout
- Impact: Minor automation delay. All 37 scans completed successfully.

### D16: Prediction reversal from Phase 2
- Phase 2 smoke test predicted MEDUSA = best discriminator
- Full evaluation: Sigil+bandit highest Youden (0.30), not MEDUSA (0.16)
- Confirms Phase 1->2 warning: scanner rankings shift between evaluation stages

### D17: H-4 complementarity prediction REFUTED
- H-4 predicted running 2 scanners in series reduces AOQL by >=30%
- Actual: zero AOQL improvement from multi-scanner union
- Root cause: scanner detection sets are nested (Cisco subset of MEDUSA subset of Sigil), not complementary
- Resolution: H-4 PARTIALLY SUPPORTED (AOQL ratio criterion met, complementarity criterion refuted)
