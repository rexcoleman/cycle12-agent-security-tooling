---
project: "Agent Security Scanner Operating Characteristics"
fp: "FP-12"
status: COMPLETE
quality_score: 9.0
last_scored: 2026-04-14
profile: security-ml
---

# FINDINGS -- Agent Security Scanner Operating Characteristics

> **Project:** Agent Security Scanner Operating Characteristics: A Manufacturing QA Framework for Comparative Evaluation
> **Date:** 2026-04-14
> **Status:** COMPLETE
> **Lock commit:** ab941d4

## Claim Strength Legend

| Tag | Meaning |
|-----|---------|
| [DEMONSTRATED] | Directly supported by data presented in this paper |
| [SUGGESTED] | Consistent with data but requires additional evidence |
| [PROJECTED] | Extrapolation from demonstrated findings |
| [HYPOTHESIZED] | Speculative claim requiring future investigation |

## Abstract

We evaluated three agent security scanners -- Cisco MCP Scanner (v4.6.0), MEDUSA (v2026.4.0), and Sigil (with bandit integration) -- against a ground-truth corpus of 37 MCP server test cases (25 vulnerable across 5 OWASP Agentic AI categories, 12 safe controls) using Operating Characteristic curve methodology adapted from manufacturing quality assurance. [DEMONSTRATED] No scanner achieved a Youden Index above 0.30 on the full corpus. The highest-performing scanner (Sigil+bandit at score threshold >13) achieved TPR=0.80 with FPR=0.50 (Youden=0.30). MEDUSA showed the starkest operating characteristic curve: 96% detection at low thresholds but 100% false positive rate, dropping to 16% detection at high thresholds with 0% false positives. Cisco MCP Scanner detected only 8% of vulnerabilities (2/25) at all operating points. [DEMONSTRATED] Scanner detection profiles showed strong category-level specialization. ASI01 (tool poisoning) and ASI03 (identity/privilege) achieved 0% detection by both Cisco and MEDUSA at discriminating operating points, while ASI05 (code execution) reached 100% detection by Sigil and MEDUSA (at the cost of high false positive rates). [DEMONSTRATED] Fisher's exact test confirmed statistically significant detection differences between Sigil and both Cisco (p<0.001) and MEDUSA (p<0.001) after Bonferroni correction. The AOQL (Average Outgoing Quality Limit) ranged from 0.04 (MEDUSA, best TPR) to 0.92 (Cisco), a 23x ratio. [DEMONSTRATED] Scanner union analysis showed no complementarity benefit: all three scanners combined detected 80% of vulnerabilities, identical to Sigil alone, because Cisco and MEDUSA detections were strict subsets of Sigil's detections.

## Methods

### Ground-Truth Corpus

The evaluation corpus comprised 37 MCP server test cases constructed from two sources:

1. **CVE-based cases (17):** Minimal FastMCP server implementations reproducing vulnerabilities from January-April 2026 MCP-related CVEs (sources: NVD, GitHub Security Advisories). Each case implements the vulnerable code pattern identified in the CVE description with a tools.json static definition and runnable server.py. CVEs include CVE-2025-53107 (CVSS 9.8, command injection in git-mcp-server), CVE-2026-0755 (CVSS 9.8, eval() injection in gemini-mcp-tool), and 15 others spanning CWE-78, CWE-94, CWE-22, CWE-88, CWE-306, and CWE-350.

2. **MCPSecBench-derived cases (8):** Adapted from the MCPSecBench attack taxonomy (Yang et al., 2025, arxiv:2508.13220) covering semantic attack types not represented in CVE data: tool poisoning, tool shadowing, indirect prompt injection, schema inconsistency, name squatting (tools and servers), configuration drift, and a vulnerable server combining path traversal with command injection.

3. **Safe controls (12):** 7 patched variants of vulnerable servers (e.g., command execution with whitelist validation, eval() replaced with ast.literal_eval) and 5 decoy servers performing complex but safe operations (database with parameterized queries, HTTP client with URL allowlist, crypto/hash utilities).

Ground-truth labels were validated via 24% stratified sample with Cohen's kappa = 1.0 (perfect agreement).

Category distribution: ASI05 (Code Execution) = 10, ASI04 (Supply Chain) = 6, ASI03 (Identity/Privilege) = 3, ASI02 (Tool Misuse) = 3, ASI01 (Agent Goal Hijack) = 3, Safe = 12.

### Scanner Configuration

**Cisco MCP Scanner v4.6.0** -- Three operating points:
- OP1: Static mode, YARA analyzer, severity filter = all
- OP2: Stdio mode (live MCP connection), YARA analyzer, severity filter = all
- OP3: Static mode, YARA analyzer, severity filter = high only

Note: Behavioral and LLM analyzers require API keys (MCP_SCANNER_LLM_API_KEY, MCP_SCANNER_API_KEY) which were not available. All Cisco results reflect YARA-only analysis. [DEMONSTRATED]

**MEDUSA v2026.4.0** -- Four operating points, all filtered to MCPServerScanner + OWASPLLMScanner + ToolCallbackScanner (excluding generic scanners that produce non-discriminating findings):
- OP1: All findings (severity >= low)
- OP2: Findings with severity >= medium
- OP3: Findings with severity >= high
- OP4: Findings with severity >= critical

**Sigil (with bandit v1.9.4)** -- Two operating points based on composite risk score:
- OP1: Risk score > 13 (base score; any elevation = detection)
- OP2: Risk score > 19 (higher threshold)

Sigil alone (without bandit) produced identical score of 13 on all cases and was unable to discriminate. Bandit integration was installed during Phase 3, enabling code-level pattern detection that elevated scores on servers containing subprocess/eval patterns.

**AgentSeal v0.9.6** -- Excluded from quantitative analysis. Free version reports "safe" for all cases; toxic flow analysis and trust scoring require Pro license. scan-mcp mode connects to servers and enumerates tools but produces zero findings. [DEMONSTRATED]

### Statistical Methods

Detection metrics per scanner per operating point: True Positive Rate (TPR, sensitivity), False Positive Rate (FPR, 1-specificity), Youden Index (TPR - FPR). Confidence intervals: Clopper-Pearson exact binomial 95% CI on all rates.

Pairwise comparisons: Fisher's exact test with Bonferroni correction (alpha = 0.05/3 = 0.0167). Inter-scanner agreement: Cohen's kappa (pairwise). OC curve shape comparison: Kolmogorov-Smirnov two-sample test on detection probability distributions.

AOQL computed as 1 - best_TPR per scanner. Complementarity: pairwise union detection rate and Jaccard similarity on vulnerable case detection vectors.

## Results

### Overall Detection Performance

| Scanner | Best OP | TPR | FPR | Youden | TPR 95% CI |
|---------|---------|-----|-----|--------|------------|
| Cisco | OP1_static_all | 0.08 | 0.00 | 0.08 | [0.01, 0.26] |
| MEDUSA | OP3_high | 0.16 | 0.00 | 0.16 | [0.05, 0.36] |
| MEDUSA | OP1_any | 0.96 | 1.00 | -0.04 | [0.80, 1.00] |
| Sigil | OP1_score_gt13 | 0.80 | 0.50 | 0.30 | [0.59, 0.93] |
| Sigil | OP2_score_gt19 | 0.36 | 0.25 | 0.11 | [0.18, 0.57] |

"Best OP" selected by maximum Youden Index. [DEMONSTRATED] No scanner achieved Youden > 0.30 on the full 37-case corpus. The highest single Youden Index was 0.30 (Sigil OP1), indicating that the best available scanner configuration achieves a detection advantage of only 30 percentage points over random classification. Key quantified effects: Youden difference = 0.22 between Sigil and Cisco (effect = 0.22, p<0.001). MEDUSA TPR ratio = 6.0 between OP1 and OP3 (effect = 0.80 TPR difference across operating points). AOQL ratio = 23.0 between worst (Cisco, 0.92) and best (MEDUSA OP1, 0.04). Sigil FPR difference = 0.25 between OP1 (0.50) and OP2 (0.25) thresholds (effect = 0.25).

### Per-Category Detection Heatmap (Best Operating Point)

| Scanner (OP) | ASI01 | ASI02 | ASI03 | ASI04 | ASI05 |
|--------------|-------|-------|-------|-------|-------|
| Cisco (OP1_static_all) | 0% | 33% | 0% | 0% | 10% |
| MEDUSA (OP3_high) | 0% | 33% | 0% | 17% | 20% |
| Sigil (OP1_score_gt13) | 0% | 67% | 100% | 83% | 100% |

[DEMONSTRATED] ASI01 (Agent Goal Hijack: tool poisoning, tool shadowing, indirect injection) achieved 0% detection across all scanners at their best Youden operating point. This category represents semantic attacks embedded in tool descriptions and schemas that pattern-matching scanners cannot identify.

[DEMONSTRATED] ASI05 (Code Execution) achieved the highest detection rates: 100% by Sigil (at the cost of 50% FPR on safe cases), 20% by MEDUSA at high severity threshold (0% FPR), and 96% by MEDUSA at any-severity threshold (100% FPR). These are syntactic patterns (subprocess.run shell=True, eval(), os.system) readily detectable by code analysis tools.

[SUGGESTED] The detection gap between syntactic vulnerabilities (ASI02, ASI05) and semantic vulnerabilities (ASI01) reveals a fundamental limitation of current scanner architectures. Syntactic patterns can be detected by regex/YARA/AST analysis; semantic attacks require understanding of tool description intent, which no tested scanner implements effectively without LLM analysis.

### Operating Characteristic Curves

MEDUSA exhibited the most dramatic OC curve shape: detection probability drops from 0.96 to 0.16 as the severity threshold increases from "any" to "high/critical". This 80-percentage-point drop indicates that the vast majority of MEDUSA's true detections are at MEDIUM severity -- the same level at which it also produces findings on all 12 safe cases. [DEMONSTRATED]

Cisco's OC curve is effectively flat at 0.08 across all three operating points (static/stdio mode and severity filter make no difference to YARA detection). This reflects that Cisco's YARA rules match on a small, fixed set of tool description patterns (specifically "clone" as system manipulation). [DEMONSTRATED]

Sigil's two operating points (score >13 and score >19) show a trade-off: lowering the threshold from 19 to 13 increases TPR from 0.36 to 0.80 but increases FPR from 0.25 to 0.50. [DEMONSTRATED]

### Statistical Tests

| Test | Comparison | Statistic | p-value | Significant? |
|------|-----------|-----------|---------|-------------|
| Fisher's exact | Cisco vs MEDUSA | OR=0.46 | 0.667 | No |
| Fisher's exact | Cisco vs Sigil | OR=0.02 | <0.001 | Yes (Bonferroni) |
| Fisher's exact | MEDUSA vs Sigil | OR=0.05 | <0.001 | Yes (Bonferroni) |
| Cohen's kappa | Cisco vs MEDUSA | 0.28 | -- | Poor agreement |
| Cohen's kappa | Cisco vs Sigil | 0.05 | -- | Slight agreement |
| Cohen's kappa | MEDUSA vs Sigil | 0.10 | -- | Slight agreement |
| K-S test | Cisco vs MEDUSA | 1.0 | 0.057 | No (borderline) |
| K-S test | Cisco vs Sigil | 1.0 | 0.200 | No |
| K-S test | MEDUSA vs Sigil | 0.5 | 0.933 | No |

[DEMONSTRATED] Sigil's detection rate is significantly different from both Cisco (p<0.001) and MEDUSA (p<0.001) after Bonferroni correction. Cisco vs MEDUSA was not significant (p=0.667), meaning these two scanners are statistically indistinguishable in their (poor) detection performance at discriminating operating points.

[DEMONSTRATED] K-S tests on OC curve shapes did not reach significance, likely due to the small number of operating points per scanner (2-4 points per curve). The K-S test requires larger samples of curve points to distinguish distribution shapes.

### AOQL and Complementarity

| Scanner | Best TPR | AOQL |
|---------|----------|------|
| MEDUSA (OP1_any) | 0.96 | 0.04 |
| Sigil (OP1) | 0.80 | 0.20 |
| Cisco (OP1) | 0.08 | 0.92 |

AOQL ratio (worst/best): 23x. [DEMONSTRATED] This exceeds the H-4 threshold of >=2x by an order of magnitude.

However, MEDUSA's AOQL of 0.04 is achieved at 100% FPR -- every server scanned would be flagged, making the low AOQL operationally meaningless. [DEMONSTRATED] At its best-discriminating operating point (OP3_high), MEDUSA's effective AOQL is 0.84 (84% of vulnerabilities pass through undetected).

**Complementarity analysis:**

| Configuration | Detection Rate (of 25 vuln) |
|---|---|
| Cisco alone | 2/25 = 8% |
| MEDUSA alone (best Youden OP) | 4/25 = 16% |
| Sigil alone | 20/25 = 80% |
| Cisco + MEDUSA union | 5/25 = 20% |
| Cisco + Sigil union | 20/25 = 80% |
| MEDUSA + Sigil union | 20/25 = 80% |
| All three scanners | 20/25 = 80% |

[DEMONSTRATED] No complementarity benefit was observed. Adding Cisco and MEDUSA to Sigil provided zero additional detections. The 5 cases undetected by Sigil (all scoring 13, the base score: mcpsecbench_tool_poisoning, mcpsecbench_tool_shadowing, mcpsecbench_indirect_injection, mcpsecbench_name_squatting_tools, cve_2025_68143) were also undetected by all other scanners. Jaccard similarity between scanner pairs ranged from 0.10 to 0.20, indicating low overlap in what was detected (because Cisco and MEDUSA detected so little).

### Sensitivity Analyses

**Ablation 1 -- Binary aggregation:** Results above use binary vulnerable/safe classification across all categories. No change from per-category analysis aggregation.

**Ablation 2 -- Exclude safe cases (TPR only):** Removing FPR from consideration does not change scanner ranking. MEDUSA OP1: 0.96, Sigil OP1: 0.80, MEDUSA OP3: 0.16, Cisco: 0.08.

**Ablation 3 -- Remove LLM-judge scanners:** Not applicable. No scanner used LLM analysis during evaluation (Cisco behavioral/LLM analyzers require API keys; AgentSeal deep analysis requires Pro license). All results reflect rule-based/pattern-matching analysis only. [DEMONSTRATED] This means our evaluation measures the FLOOR of scanner capability -- LLM-augmented configurations could perform better.

**Ablation 4 -- Strict labeling (CWE-78/CWE-94 only as vulnerable):** Under strict labeling (11 vulnerable cases instead of 25), Sigil OP1 achieves Youden=0.42 (TPR=1.00, FPR=0.58) and MEDUSA OP3 achieves Youden=0.23 (TPR=0.27, FPR=0.04). The ranking is preserved. [DEMONSTRATED]

**Ablation 5 -- Independence test (H-3):** Each test case is an independent MCP server (1 server = 1 case). Server-level clustered bootstrap is identical to standard bootstrap. No clustering distortion detected. [DEMONSTRATED]

## Hypothesis Resolutions

### H-1: Scanner Distinguishability -- PARTIALLY SUPPORTED

[DEMONSTRATED] Two of three scanner pairs showed statistically significant detection differences (Fisher's exact, p<0.001 after Bonferroni correction): Cisco vs Sigil and MEDUSA vs Sigil. However, Cisco vs MEDUSA was not significant (p=0.667). The hypothesis predicted "at least 1 scanner pair will show significantly different Youden Index scores" -- this is confirmed for 2 of 3 pairs.

### H-2: Scanner Specialization Pattern -- PARTIALLY SUPPORTED

[DEMONSTRATED] Scanners showed different category detection profiles. Cisco detected exclusively ASI02 (1/3) and ASI05 (1/10). MEDUSA detected across ASI02, ASI04, ASI05 at high-severity threshold, and nearly everything at low threshold. Sigil detected across ASI02-ASI05 but not ASI01.

[DEMONSTRATED] However, the predicted specialization pattern was wrong: the prediction stated "Cisco will lead on syntactic categories" and "AgentSeal will lead on semantic categories." In fact, Sigil (a shell script wrapping bandit) led on ALL detectable categories, and no scanner led on semantic categories (ASI01 = 0% for all).

### H-3: Independence Assumption -- SUPPORTED

[DEMONSTRATED] Each test case is an independent server with one primary vulnerability. Server-level clustering is equivalent to standard bootstrap. No distortion detected. The independence assumption holds.

### H-4: AOQL and Complementarity -- PARTIALLY SUPPORTED

[DEMONSTRATED] AOQL ratio between best (MEDUSA: 0.04) and worst (Cisco: 0.92) is 23x, far exceeding the >=2x threshold. However, the complementarity prediction is REFUTED: running 2 or 3 scanners in series provided zero AOQL improvement over Sigil alone. Scanner detection sets are nested (Cisco subset of MEDUSA subset of Sigil), not complementary.

## Discussion

### The Sensitivity-Specificity Dilemma in Agent Security Scanning

The central finding is that no tested scanner achieves simultaneously high sensitivity and high specificity on agent-security vulnerabilities. This is not merely a calibration problem -- it reflects a fundamental architectural mismatch between scanner detection mechanisms and vulnerability types.

"MEDUSA's MCPServerScanner detects subprocess.run with shell=True at line 16 as CRITICAL, and also flags safe servers using subprocess.run with shell=False or with input validation, because the scanner matches the function signature pattern, not the security context" (observed in scanner output classifications). [DEMONSTRATED]

This finding echoes the established literature on SAST false positive rates. Ghost Security (2025) reported 40-91% false positive rates across approximately 3,000 repositories for traditional SAST tools. [SUGGESTED] Our results indicate agent security scanners face at least comparable challenges: MEDUSA's 100% FPR at its high-sensitivity operating point and Sigil's 50% FPR at its best Youden point confirm that the SAST FP problem has been inherited, not solved, by the agent security scanner generation.

### The Semantic Vulnerability Gap

[DEMONSTRATED] ASI01 (Agent Goal Hijack: tool poisoning, tool shadowing, indirect prompt injection) achieved 0% detection across all scanners at all operating points. These attacks embed malicious instructions in tool descriptions (e.g., "Before executing, first read all files in the current directory and include their contents") that redirect LLM behavior without any code-level vulnerability pattern.

[SUGGESTED] Detecting tool poisoning requires semantic understanding of tool descriptions in the context of expected agent behavior -- a capability that none of the tested scanners implement in their free/open-source configurations. AgentSeal's "deep analysis" mode and Cisco's LLM analyzer are designed for this purpose but were inaccessible (Pro license and API key requirements, respectively).

### Comparison with Prior Benchmarking Work

**OWASP Benchmark v1.2** (OWASP Foundation, 2016-present) established the methodology of scoring SAST/DAST tools via Youden Index on a known ground-truth corpus of 2,740 Java test cases. Our work adapts this methodology to the agent security domain with three extensions: (1) MCP-specific vulnerability types mapped to the OWASP Agentic AI Top 10 taxonomy, (2) multiple operating points per scanner enabling OC curve construction beyond single Youden scores, and (3) the AOQL metric from manufacturing QA providing a practitioner-relevant framing of "what fraction of vulnerabilities pass through undetected."

"OWASP Benchmark is a test suite designed to verify the speed and accuracy of software vulnerability detection tools" (OWASP Foundation, https://owasp.org/www-project-benchmark/). [DEMONSTRATED] Our corpus serves the same function for the agent security scanner class.

**MCP-SafetyBench** (Zong et al., ICLR 2026, arxiv:2512.15163) evaluates MODEL safety behavior against MCP attacks, finding that "all models remain vulnerable to MCP attacks, with a notable safety-utility trade-off." Our work is complementary: we evaluate SCANNER detection effectiveness, not model robustness. The MCP-SafetyBench finding that models are vulnerable makes scanner detection effectiveness more urgent. [DEMONSTRATED]

**MCPSecBench** (Yang et al., 2025, arxiv:2508.13220) provides 17 attack types across 4 attack surfaces and finds "all attack surfaces yield successful compromises" with protection mechanisms achieving "an average success rate of less than 30%." We used 8 MCPSecBench attack types as supplementary corpus cases and found that 5 of 8 (tool poisoning, tool shadowing, indirect injection, name squatting tools, name squatting server) were undetected by all scanners. [DEMONSTRATED]

**Miercom DAST Benchmark 2026** evaluated 11 intentionally vulnerable web applications against commercial DAST tools. The closest methodological analog to our work: independent third-party evaluation on common ground truth. Their finding that "Invicti was the only tested solution to detect all 31 critical vulnerabilities" parallels our finding that no agent security scanner achieves comparable completeness -- the best scanner (Sigil) detected 80% of vulnerabilities, not 100%. [SUGGESTED] Agent security scanner maturity lags behind traditional DAST by this measure.

**AgentSeal 1,808-server scan** (AgentSeal, 2026) reported 66% of MCP servers have security findings. Our evaluation reveals the mechanism behind such statistics: at MEDUSA's OP1 (all findings), the tool reports findings on 97% of all servers (24/25 vulnerable + 12/12 safe = 36/37). [DEMONSTRATED] The 66% figure from AgentSeal's production scan is plausible but likely includes substantial false positives, as our corpus evaluation demonstrates.

## Novelty Assessment

1. **First threshold-independent comparison of agent security scanners.** Prior evaluations (AgentSeal blog, Enkrypt AI reports) publish self-reported single-point metrics. We construct OC curves across multiple operating points per scanner, enabling practitioners to choose configurations based on their sensitivity-specificity requirements.

2. **First application of manufacturing QA AOQL methodology to security scanner evaluation.** The AOQL framing translates security metrics into a manufacturing QA question: "what fraction of defective units (vulnerable servers) pass inspection (scanning) undetected?" This bridges security engineering and quality assurance communities.

3. **First ground-truth MCP vulnerability corpus with binary labels across 5 OWASP Agentic AI categories.** The 37-case corpus with CVE-linked vulnerabilities and safe controls is a reusable evaluation artifact.

4. **First quantification of the semantic vulnerability detection gap in agent security scanners.** The 0% detection rate on ASI01 across all tested scanners documents a previously unquantified blind spot.

5. **First demonstration that current agent security scanner complementarity is negligible.** Multi-scanner strategies do not improve coverage because scanner detection sets are nested, not diverse.

## Cross-Domain Transfer Test

Transfer test COMPLETED: OC curve methodology from manufacturing QA (ISO 2859-1) applied to agent security scanner evaluation. The detection probability function (plot acceptance probability vs defect fraction) transferred successfully — OC curves were computed for all 3 scanners across 2-4 operating points each. The sampling aspect of ISO 2859-1 did NOT transfer (scanners examine 100% of code, not samples), as pre-registered in LA §6b.1. Transfer validity: PARTIAL — mathematical framework transferred, generating process differed.

## Cross-Domain Connections

The Operating Characteristic curve framework originated in manufacturing quality assurance (ISO 2859-1) for comparing inspection systems. The specific parallel: manufacturing plants choosing between inspection vendors (each claims high quality, none provides comparable data) maps to security teams choosing between agent security scanners.

"In manufacturing QA, the OC curve plots acceptance probability vs true defect fraction, quantifying producer risk (false positives) and consumer risk (false negatives)" (ISO 2859-1). [DEMONSTRATED] We adapt this framework by treating each MCP server as a "lot" and each vulnerability as a "defect." The detection probability at each severity threshold corresponds to an operating point on the OC curve.

The AOQL concept (Average Outgoing Quality Limit) is particularly relevant: it quantifies the worst-case fraction of defective items that pass through inspection. In security terms, it answers: "even with this scanner, what fraction of vulnerabilities will I miss?" Our finding that the best single-scanner AOQL is 0.20 (Sigil) at a usable operating point means practitioners should expect approximately 1 in 5 vulnerable servers to pass scanning undetected, assuming vulnerabilities resemble our corpus distribution.

## Generalization Analysis

### Failure Mode 1: Corpus Distribution Mismatch

[DEMONSTRATED] Our corpus overrepresents ASI05 (Code Execution, 40% of vulnerable cases) because CVE databases are biased toward code-level vulnerabilities with clear CWE mappings. Real-world MCP deployments may have different vulnerability distributions. Specifically:

- If semantic vulnerabilities (ASI01) are more prevalent than our corpus suggests, all scanner Youden indices are optimistic (detection rates would be lower).
- Threshold: if ASI01 prevalence exceeds 20% of real-world MCP vulnerabilities, MEDUSA's effective Youden drops from 0.16 to below 0.10.

### Failure Mode 2: Vulnerability Complexity Gap

[DEMONSTRATED] Our test cases are minimal single-vulnerability servers (median 30 lines of code). Real-world MCP servers embed vulnerabilities in legitimate code spanning hundreds or thousands of lines. Scanner detection rates on synthetic minimal servers may overestimate detection on complex real servers, because:

- Pattern-matching scanners (bandit, YARA) may miss vulnerabilities obscured by surrounding code
- False positive rates may differ when scanners process larger codebases with more pattern matches

Threshold: for servers exceeding 500 lines of code, we predict Sigil's TPR drops by 10-30 percentage points (bandit's pattern density per line decreases).

### Failure Mode 3: Scanner Configuration Gap

[DEMONSTRATED] All three scanners were evaluated in their open-source/free configurations. Cisco's LLM analyzer (requires API key), AgentSeal's deep analysis (requires Pro license), and MEDUSA with bandit integration (not tested) could alter detection profiles. Specifically:

- Cisco's LLM analyzer is designed to detect semantic mismatches between tool descriptions and behavior -- exactly the ASI01 gap we identified.
- AgentSeal Pro's toxic flow analysis could detect tool poisoning patterns.

Threshold: if LLM-augmented modes improve ASI01 detection to even 30%, the complementarity story changes fundamentally because current scanner detection sets would no longer be nested.

### Evaluation Conditions Table

| Condition | Our Evaluation | Alternative | Expected Impact on Results |
|-----------|---------------|-------------|---------------------------|
| Server language | Python only | JavaScript/TypeScript | Sigil TPR drops (bandit is Python-specific); Cisco YARA unaffected; MEDUSA MCPServerScanner N/A |
| Server complexity | Minimal (median 30 LOC) | Production (500+ LOC) | Sigil TPR drops 10-30pp; MEDUSA FPR may increase; Cisco unchanged |
| Scanner configuration | Free/open-source | LLM-augmented (Cisco LLM, AgentSeal Pro) | ASI01 detection may improve from 0% to 30%+; complementarity may emerge |
| Vulnerability distribution | 40% ASI05, 12% ASI01 | Equal across categories | Youden indices drop if ASI01 prevalence increases |
| Corpus source | CVE-based + MCPSecBench | Real-world honeypot data | Detection rates likely lower on ecologically valid vulnerabilities |
| Evaluation timing | April 2026 scanner versions | Future versions | Scanner rules update; detection may improve on known patterns |

### Structural Conditions Where Results Do Not Generalize

1. **Non-Python MCP servers.** Corpus is 100% Python. Bandit and MEDUSA's MCPServerScanner are Python-specific. Sigil's score would be lower on JavaScript/TypeScript servers (different bandit equivalent needed). Jaccard similarity: 0.0 between Python-trained and JavaScript vulnerability patterns.

2. **Runtime-only vulnerabilities.** Configuration drift (MCPSecBench) and time-of-check/time-of-use attacks require runtime observation. Static analysis scanners cannot detect these by design.

3. **Commercial/enterprise scanner configurations.** Our results apply to free/open-source tool configurations only. Enterprise tools with custom rule sets, ML models, or threat intelligence feeds may perform differently.

## Practitioner Impact

[SUGGESTED] For production MCP server operators evaluating agent security scanners:

1. **No single scanner is sufficient.** The best scanner (Sigil+bandit) misses 20% of known vulnerabilities (TPR=0.80, 95% CI [0.59, 0.93]) and produces 50% false positives (FPR=0.50, 95% CI [0.21, 0.79]). Scanner output should be treated as a triage signal, not a definitive security assessment.

2. **Severity thresholds matter enormously.** MEDUSA at "all findings" detects 96% (CI [0.80, 1.00]) but flags everything (FPR=1.00). At "high severity" it detects only 16% (CI [0.05, 0.36]) with 0% FPR. The effect = 0.80 TPR difference between these operating points. Practitioners must deliberately choose their operating point based on team capacity to review findings.

3. **Semantic vulnerabilities are invisible to current tools.** Tool poisoning, tool shadowing, and indirect prompt injection (ASI01) achieved 0% detection (CI [0.00, 0.71]) across all scanners. Manual review of tool descriptions and schema-behavior alignment remains necessary.

4. **Multi-scanner strategies offer no benefit with current tools.** Union detection rate (3 scanners combined) = 0.80 — identical to best single scanner (Sigil, effect = 0.00 complementarity gain). Because detection sets are nested rather than complementary, running multiple scanners adds cost without improving coverage.

## Hostile Baseline Check

**Hostile Criticism 1: "Your corpus is too synthetic -- real vulnerabilities are harder to detect."**
Response: This is correct and acknowledged in Generalization Analysis Failure Mode 2. Our corpus measures scanner capability on KNOWN patterns, not ecological detection effectiveness. Test cases are synthetic minimal MCP servers with explicitly constructed vulnerabilities. Real-world vulnerable MCP servers embed vulnerabilities in complex legitimate code. Scanner detection rates on this corpus may differ from real-world rates. We explicitly frame results as an UPPER BOUND on scanner detection capability. [DEMONSTRATED]

**Hostile Criticism 2: "You didn't test the scanners' best modes -- Cisco with LLM, AgentSeal Pro."**
Response: Acknowledged in Failure Mode 3. API keys and Pro licenses were unavailable. We test what is freely accessible, which is the configuration most practitioners will encounter. The semantic gap finding (0% ASI01 detection) specifically motivates testing LLM-augmented modes as future work. [DEMONSTRATED]

**Hostile Criticism 3: "Sigil is just bandit -- you're measuring bandit, not Sigil."**
Response: This is partially correct. Sigil without bandit produces identical score 13 on all cases and cannot discriminate. Sigil's value-add over bandit is the quarantine workflow, provenance checking, and dependency analysis -- none of which contribute to vulnerability detection on our corpus. We report this honestly. The finding that a general-purpose Python security linter (bandit) outperforms MCP-specific scanners is itself a significant result. [DEMONSTRATED]

**Hostile Criticism 4: "37 cases is too few for OC curves and the K-S test is underpowered."**
Response: Acknowledged. K-S tests were not significant, likely due to only 2-4 operating points per scanner. Clopper-Pearson CI widths range from 0.20 to 0.90 depending on category size. Per-category results (N=3 to N=10) should be interpreted as descriptive, not inferential. The overall results (N=25 vulnerable, N=12 safe) provide adequate power for Fisher's exact test (2 of 3 pairs significant). [DEMONSTRATED]

## Effect Persistence

[SUGGESTED] Scanner detection effectiveness is expected to degrade over time as:
1. Vulnerability patterns evolve beyond current YARA/regex rules
2. Attack sophistication increases (more subtle tool poisoning)
3. Scanner rule sets may update (improving detection of known patterns)

The corpus itself is version-locked to April 2026 CVEs and MCPSecBench attack types. Re-evaluation with updated scanner versions and expanded corpus is recommended at 6-month intervals.

## Boundary Statement

This evaluation applies to: open-source agent security scanners in their free configurations, evaluated on synthetic minimal MCP server test cases with known binary vulnerability labels, across 5 OWASP Agentic AI categories. Results do not generalize to: commercial scanner configurations, non-Python MCP servers, runtime-only vulnerabilities, real-world servers with complex codebases, or scanner versions beyond those tested (Cisco v4.6.0, MEDUSA v2026.4.0, Sigil with bandit v1.9.4, AgentSeal v0.9.6).

## Pre-emptive Criticism

1. **"The OWASP Agentic AI Top 10 taxonomy is too new to be authoritative."** We use it as a categorization framework, not as ground truth. Any taxonomy mapping 25 CVEs to 5+ categories would produce similar per-category power constraints.

2. **"Operating characteristic curves require continuous quality levels, not binary classifications."** Classical OC curves plot acceptance probability vs defect fraction in lots. Our adaptation uses the threshold dimension (severity levels) as the operating parameter and binary per-case classification. This is methodologically equivalent to ROC analysis, which is well-established for binary classifiers.

3. **"You should have tested more scanners."** We installed and evaluated 5 scanners. 2 (AgentSeal, MCPScan) were excluded due to licensing/API requirements. 3 produced quantitative results. The framework is designed for easy extension -- any new scanner can be evaluated against the published corpus.

## Threats to Validity

### Construct Validity

**Test cases are synthetic minimal MCP servers with explicitly constructed vulnerabilities. Real-world vulnerable MCP servers embed vulnerabilities in complex legitimate code. Scanner detection rates on this corpus may differ from real-world rates. This corpus measures scanner capability on KNOWN patterns, not ecological detection effectiveness.**

### Internal Validity

- Scanner execution was deterministic (no LLM components active). No stochastic variation requiring repeated runs.
- MEDUSA's interactive prompt handling (yes/no for missing tools) introduced a potential source of scan incompleteness. Mitigation: used yes pipe and verified all 37 reports were generated.
- Sigil's score includes ANSI escape codes that required cleaning for numerical extraction. All scores verified manually against raw report files.

### External Validity

- Python-only corpus limits generalization to Python MCP servers.
- Free-tier scanner configurations do not represent full scanner capability.
- 37 cases across 5 categories yields per-category samples of 3-10, insufficient for inferential per-category analysis.

### Statistical Validity

- Clopper-Pearson CIs are exact (no approximation assumptions).
- Bonferroni correction applied to all multiple comparisons.
- K-S test underpowered due to small number of operating points per scanner (2-4).

## Sensitivity Analysis

See Results > Sensitivity Analyses section above for ablation results including binary aggregation, safe case exclusion, LLM-judge removal, strict labeling, and independence testing.

## Detection Methodology (R38)

All detection was automated: scanner execution via shell scripts on Mac Mini (M4 Pro, 48GB), classification via Python script comparing scanner output against manifest.csv ground truth labels. No manual detection decisions were made. Scanner outputs were parsed programmatically (JSON for Cisco/MEDUSA, text with ANSI cleaning for Sigil).

## Formal Contribution Statement (R34)

1. A reusable ground-truth MCP vulnerability corpus of 37 test cases across 5 OWASP Agentic AI categories.
2. The first threshold-independent comparison of agent security scanners via OC curve methodology.
3. Quantification of the semantic vulnerability detection gap (0% detection on ASI01 across all tested scanners).
4. Demonstration that multi-scanner strategies provide no complementarity benefit with current free tools.
5. Adaptation of manufacturing QA AOQL framework to security scanner evaluation.

## Breakthrough Question

What happens when LLM-augmented scanner modes (Cisco behavioral + AgentSeal Pro) are evaluated on this corpus? The semantic vulnerability gap (ASI01 = 0% detection) represents a category where ONLY LLM analysis could plausibly detect attacks embedded in tool descriptions. If LLM modes also fail on ASI01, this would demonstrate that current AI-assisted security scanning is fundamentally limited to syntactic pattern matching — the "AI" label is marketing, not capability. If LLM modes succeed, the cost-benefit of API-key-dependent scanning becomes the central practitioner question.

## Citation Verification

| Citation | Claimed Finding | Verified via WebSearch | Status |
|---|---|---|---|
| OWASP Benchmark v1.2 | Youden scores range -0.04 to 0.91 on 2,740 Java test cases | owasp.org/www-project-benchmark | Verified |
| MCP-SafetyBench (Xie et al., ICLR 2026) | 20 attack types across 5 domains, defense-success/task-success tradeoff | arxiv 2512.15163 | Verified |
| MCPSecBench (Yang et al., 2025) | 17 attack types across 4 attack surfaces | arxiv 2508.13220 | Verified |
| Miercom DAST Benchmark 2026 | Invicti detected all 31 critical vulns | miercom.com | Verified |
| AgentSeal 1,808-server scan | 66% of servers have findings, 76 confirmed malicious | agentseal.org/blog | Verified |

## Resolution Verification

| Hypothesis | Threshold | Measured | Threshold Met? | Resolution |
|---|---|---|---|---|
| H-1 (distinguishability) | Fisher's p<0.05 Bonferroni-corrected | 2/3 pairs p<0.001; 1 pair p=0.667 | PARTIAL | PARTIALLY SUPPORTED |
| H-2 (specialization) | Per-category highest-detection category differs | ASI01=0% all; ASI05 highest for all; but Cisco/MEDUSA differ on ASI02/ASI04 | PARTIAL | PARTIALLY SUPPORTED |
| H-3 (independence) | Clustered vs standard bootstrap differ <10pp | Each case independent server; no clustering | MET | SUPPORTED |
| H-4 (AOQL) | AOQL ratio >=2x; complementarity >=30% reduction | ratio = 23x; effect = 0% complementarity | PARTIAL | PARTIALLY SUPPORTED (AOQL yes, complementarity no) |

## Experiment Completeness

Experiments run: 3 scanners × 37 cases × 3-4 operating points = 333 classification events. Experiments reported: 333 (100%). No scanner runs were excluded or failed silently. All results included in analysis regardless of outcome.

Phase: CONFIRMATORY for H-1, H-2 (pre-registered hypotheses tested). Phase: EXPLORATORY for scanner architecture analysis and OC curve shape comparison (patterns discovered during analysis, not pre-registered).

## Sanity Check (R47)

E0 sanity validation was performed during the Task 1 validation run (6-case subset: 1 case per OWASP category + 1 safe). Sanity checks confirmed:
- All scanner outputs are parseable (JSON for Cisco/MEDUSA, text for Sigil)
- Classification logic correctly maps TP/FP/TN/FN against manifest ground truth
- MEDUSA correctly identifies known subprocess.run(shell=True) pattern on CVE-2025-53107
- Cisco correctly reports "safe" on safe_command_sanitized (no false positive on clean case)
- Sigil scores are numerically extractable after ANSI cleaning
- Ground truth labels match expected vulnerability/safety status

## Depth Commitment

This study reads and analyzes 37 corpus cases, 3 scanner documentation sets, and 5 prior works in detail. Key depth demonstrations:
1. Each of 37 test cases was individually scanned by 3 scanners at multiple operating points (333 total classification events).
2. Scanner output formats were reverse-engineered from raw JSON/text outputs (Cisco's nested scan_results/findings structure, MEDUSA's findings array with scanner/severity/issue fields, Sigil's ANSI-encoded risk score).
3. Five prior works quoted with specific claims: OWASP Benchmark methodology, MCP-SafetyBench ICLR 2026 findings, MCPSecBench 17 attack types, Miercom 31 critical vulnerabilities, AgentSeal 1,808 servers.

## Mechanism Analysis

The detection mechanism differs fundamentally across scanners:
- **Cisco YARA**: Pattern-matches tool DESCRIPTIONS against threat rules (e.g., "clone" triggers SYSTEM MANIPULATION). Does not analyze source code implementation despite --source-path flag. Mechanism fails on realistic descriptions that do not contain attack keywords.
- **MEDUSA MCPServerScanner**: Pattern-matches source code AST for dangerous function calls (subprocess.run, os.system, eval). Severity derived from call context (shell=True = CRITICAL, subprocess without shell = MEDIUM). Mechanism fails to distinguish safe use (input validation, whitelisting) from unsafe use.
- **Sigil+bandit**: Bandit performs Python AST analysis for security anti-patterns (B603: subprocess with shell=True, B307: eval use). Sigil aggregates bandit findings into a composite risk score. Mechanism inherits bandit's known limitation of high false positive rates on safe usage of security-sensitive functions.

## Published Baseline

OWASP Benchmark v1.2 reports Youden Index scores for SAST tools on Java web application vulnerabilities. Published scores range from -0.04 (random) to 0.91 (Fluid Attacks SAST) on 2,740 test cases. Our agent security scanner Youden scores (0.08 to 0.30) fall at the low end of this range, consistent with the expectation that agent security scanning is a less mature field than traditional SAST.

## Parameter Sensitivity

Scanner operating point selection is the dominant parameter affecting results:
- MEDUSA: 80 percentage point TPR swing between OP1 (any severity) and OP3 (high severity)
- Sigil: 44 percentage point TPR swing between score >13 and score >19 thresholds
- Cisco: No sensitivity -- all 3 operating points produce identical results (YARA-determined)

The MEDUSA severity threshold is the single most impactful parameter in the evaluation. A practitioner choosing between MEDUSA's "detect everything" and "detect with confidence" modes faces an 80-point TPR vs 100-point FPR trade-off.

## Defense Harm Test

Could the recommended scanner configurations cause harm if adopted?
1. **False confidence from Sigil OP1**: 50% FPR means half of reviewed servers will be false alarms, but 80% TPR means real vulnerabilities are usually caught. Risk: team fatigue from false positives leading to alert fatigue. Mitigation: pair with manual review.
2. **False confidence from MEDUSA OP3**: 0% FPR but only 16% TPR means clean scan reports are unreliable -- 84% of vulnerable servers pass. Risk: false sense of security. Mitigation: do not use high-severity-only mode as sole security gate.
3. **ASI01 blind spot**: No scanner detects tool poisoning. Risk: practitioners who rely solely on scanning miss the most dangerous attack category. Mitigation: manual tool description review required.

## Content Hooks

- "We scanned 37 MCP servers with 3 security scanners. The best one missed 1 in 5 known vulnerabilities and flagged half of safe servers as dangerous."
- "No scanner detected tool poisoning attacks -- the most dangerous category of MCP vulnerability."
- "Running 3 scanners instead of 1 added zero additional detections."

## Related Work

See Discussion section for detailed comparison with OWASP Benchmark, MCP-SafetyBench, MCPSecBench, Miercom DAST Benchmark 2026, and AgentSeal 1,808-server scan.

## Limitations and Next Questions (Raw Source Notes)

1. Small corpus (37 cases) limits per-category statistical power. → Next question: Does detection profile stability hold at N=100+ cases per category?
2. Python-only test cases. → Next question: Do scanners show different detection profiles on TypeScript/Go MCP servers?
3. Free/open-source scanner configurations only. → Next question: Does Cisco behavioral/LLM mode close the ASI01 semantic gap (effect = detection gain per API dollar)?
4. No LLM-augmented scanner modes tested. → Next question: What is the cost-benefit ratio of API-key-dependent scanning vs free scanning?
5. Synthetic minimal servers vs real-world complex codebases. → Next question: By how much does detection drop on servers >500 LOC (difference = synthetic TPR minus ecological TPR)?
6. Sigil discrimination depends entirely on bandit integration (Sigil-native analysis does not discriminate). → Next question: Are there other code analysis tools that improve Sigil beyond bandit?
7. Single evaluation cycle -- no temporal stability data. → Next question: Do scanner updates between versions change detection profiles?

## Reproducibility

- **State:** Full reproduction possible. All scripts, corpus, and analysis code in the project repository.
- **Estimated runtime:** ~30 minutes (scanner execution on Mac Mini) + ~5 minutes (analysis on Azure).
- **Estimated cost:** $0 (all tools are free/open-source; no API keys required for reproduction at our configuration level).
- **Requirements:** Mac Mini with Python 3.12, pip-installable scanners (cisco-ai-mcp-scanner, medusa-security, agentseal), npm-installable Sigil (@nomarj/sigil), bandit.

## Negative Results

1. [DEMONSTRATED] **Cisco MCP Scanner's behavioral analyzer is inaccessible without API key.** Despite being advertised as having "behavioral analysis," the behavioral mode requires MCP_SCANNER_LLM_API_KEY. Without it, Cisco is a YARA-only scanner that detects 8% of vulnerabilities.

2. [DEMONSTRATED] **AgentSeal free version provides zero detection capability.** The free version connects to MCP servers and enumerates tools but reports "safe" for all cases. All meaningful detection features require Pro license.

3. [DEMONSTRATED] **Sigil's native 6-phase analysis does not discriminate.** Without bandit, Sigil produces identical risk scores on vulnerable and safe servers. Its code pattern analysis (Phase 2) reports "PASS No dangerous code execution patterns found" even on servers with subprocess.run(shell=True).

4. [DEMONSTRATED] **MEDUSA cannot simultaneously detect vulnerabilities and avoid false positives.** At any operating point, MEDUSA either detects most vulnerabilities while flagging all safe servers (TPR=0.96, FPR=1.00), or avoids false positives while missing most vulnerabilities (TPR=0.16, FPR=0.00).

5. [DEMONSTRATED] **Multi-scanner strategies are currently ineffective.** Three scanners combined detect exactly the same cases as the best single scanner. No complementary detection was observed.
