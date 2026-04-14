# Roadmap: Agent Security Scanner Operating Characteristics

## Phase 1: EDA — Validate Critical Unknowns

**Host:** Mac Mini (48GB, M4 Pro) for scanner installation; Azure for analysis

### Tasks

1. **CVE corpus feasibility assessment**
   - Search terms: NVD API query `keyword=MCP AND keyword=server`, GitHub Security Advisories for `mcp-server-*` packages
   - Download all MCP-related CVEs from Jan-Feb 2026 (expected ~30). Record: CVE ID, CVSS score, affected component, CWE mapping, description, exploit availability
   - Classify each CVE by OWASP Agentic AI Top 10 category (use taxonomy from owasp.org/www-project-agentic-ai)
   - Assess reproducibility: can a test case (vulnerable MCP server configuration) be constructed from the CVE description? Score each: reproducible / partially reproducible / description-only
   - Expected output: `outputs/eda/cve_feasibility.csv` with columns [cve_id, cvss, cwe, owasp_category, reproducibility_score, notes]
   - **Kill check:** If <15 CVEs are reproducible or partially reproducible across >=3 OWASP categories, activate supplementation from MCPSecBench attack scripts

2. **MCPSecBench attack script inventory**
   - Clone MCPSecBench repo: `git clone https://github.com/AIS2Lab/MCPSecBench.git`
   - Inventory 17 attack types: for each, document attack type, OWASP category mapping, whether it produces a scannable MCP server artifact (vs requiring runtime interaction), test case construction feasibility
   - Expected output: `outputs/eda/mcpsecbench_inventory.csv`

3. **Scanner installation and output format survey**
   - Install on Mac Mini: AgentSeal (`pip install agentseal`), Cisco MCP Scanner (`pip install mcpscanner`), MEDUSA (`pip install medusa-scan`), Ant Group MCPScan (clone from GitHub), Sigil (`npm install -g sigilsec`)
   - Run each scanner against 3 test targets: (a) a known-vulnerable MCP server from CVE corpus, (b) a known-safe minimal MCP server, (c) a moderate-complexity MCP server from public registries
   - Document output format for each scanner: JSON schema, finding fields, severity levels, category labels
   - Map each scanner's output fields to TP/FP/TN/FN classification scheme
   - Expected output: `outputs/eda/scanner_output_formats.md` with format documentation and mapping rules

4. **Scanner threshold configurability check**
   - For each installed scanner: document whether severity/sensitivity thresholds are configurable (CLI flags, config files, rule set selection)
   - If configurable: identify 3+ operating points (e.g., low/medium/high sensitivity) for OC curve construction
   - If NOT configurable: document as binary (single operating point) — this determines whether full OC curves or Youden-only comparison
   - Expected output: `outputs/eda/threshold_configurability.md`

5. **Statistical power estimation**
   - Given corpus size from Task 1, estimate: (a) power for overall Fisher's exact test at N test cases, (b) minimum detectable effect size (difference in detection rates between scanners), (c) feasibility of per-category analysis vs supercategory aggregation
   - Expected output: `outputs/eda/power_analysis.md`

### Dependencies
- Mac Mini accessible via Tailscale
- NVD API accessible (no API key required for basic queries)
- Open-source scanners installable without license keys

### Verification
- [ ] CVE feasibility CSV produced with >=25 entries classified
- [ ] >=3 scanners installed and producing parseable output on test targets
- [ ] Threshold configurability documented for all installed scanners
- [ ] Power analysis completed and kill conditions evaluated
- [ ] EDA summary decision: PROCEED to Phase 2 / MODIFY methodology / KILL project

### Kill condition evaluation at Phase 1 exit
If <15 reproducible test cases AND MCPSecBench supplementation insufficient: KILL or pivot to inter-scanner agreement analysis (without ground truth)
If <3 scanners parseable: KILL or reduce to pairwise comparison
If no scanner has configurable thresholds: MODIFY — Youden-only comparison, no full OC curves

---

## Phase 2: Ground-Truth Corpus Construction

**Host:** Mac Mini for MCP server setup and testing; Azure for corpus documentation

### Tasks

1. **Construct known-vulnerable test cases**
   - For each reproducible CVE from Phase 1: create a minimal MCP server configuration that contains the vulnerability
   - For MCPSecBench supplementation cases: adapt attack scripts into scannable MCP server artifacts
   - Each test case: unique ID, OWASP category, CVE/source reference, vulnerable code/config, expected scanner behavior (what SHOULD be detected)
   - Target: >=20 known-vulnerable test cases across >=3 OWASP categories
   - Expected output: `outputs/corpus/vulnerable/` directory with one directory per test case containing server code + manifest.json

2. **Construct known-safe control cases**
   - Create minimal MCP servers that are functionally similar to vulnerable cases but with vulnerabilities patched
   - Also include 5+ "decoy" cases: servers with complex but safe code (tests FP rates)
   - Target: >=10 known-safe test cases
   - Expected output: `outputs/corpus/safe/` directory

3. **Ground-truth labeling and validation**
   - Create corpus manifest: `outputs/corpus/manifest.csv` with columns [test_case_id, category, ground_truth_label, source_cve, confidence, notes]
   - Cross-validate labels against CVE descriptions and CVSS scores
   - 20% sample manual review: independently re-label 20% of cases, compute Cohen's kappa for inter-rater agreement (target > 0.6)
   - Expected output: `outputs/corpus/manifest.csv` + `outputs/corpus/labeling_validation.md`

4. **Corpus documentation**
   - Write corpus README with: taxonomy mapping, construction methodology, usage instructions, known limitations
   - Expected output: `outputs/corpus/README.md`

### Dependencies
- Phase 1 EDA completed with PROCEED decision
- CVE feasibility assessment completed
- MCP server runtime environment available on Mac Mini

### Verification
- [ ] >=15 total test cases (vulnerable + safe) with ground-truth labels
- [ ] >=3 OWASP categories represented with >=3 cases each (or documented justification for supercategory aggregation)
- [ ] Inter-rater kappa > 0.6 on 20% validation sample
- [ ] Corpus manifest complete and internally consistent
- [ ] All vulnerable test cases traceable to CVE or MCPSecBench source

---

## Phase 3: Scanner Evaluation + OC Curve Computation

**Host:** Mac Mini for scanner execution; Azure for statistical analysis

### Tasks

1. **Scanner execution**
   - Run each scanner (>=3 from Phase 1) against the complete corpus
   - For stochastic scanners (LLM-judge components): 3 runs per test case, record all results
   - For deterministic scanners: 1 run per test case
   - Record raw output: `outputs/scanner_results/{scanner_name}/{test_case_id}/run_{n}.json`
   - If scanners have configurable thresholds: run at each identified operating point (from Phase 1 Task 4)

2. **Output classification**
   - Map scanner outputs to TP/FP/TN/FN using mapping rules from Phase 1 Task 3
   - For stochastic scanners: use majority-vote across 3 runs for classification
   - Record classification: `outputs/analysis/classifications.csv` with columns [test_case_id, scanner, run, finding, classification, ground_truth, match]
   - Flag ambiguous cases for manual review

3. **Detection metric computation**
   - Per scanner, per category: TPR, FPR, Youden Index, with Clopper-Pearson 95% CI
   - Overall per scanner: aggregate TPR, FPR, Youden Index
   - Per-category detection heatmap: scanners x categories matrix of detection rates
   - Expected output: `outputs/analysis/detection_profiles.csv`, `outputs/figures/detection_heatmap.png`

4. **OC curve computation (if threshold-configurable scanners exist)**
   - For each configurable scanner: plot detection probability (1 - FNR) vs vulnerability density at each operating point
   - Compute area under detection curve (AUC analog)
   - Compare OC curve shapes: steep (discriminating) vs flat (unreliable)
   - If NO scanner has configurable thresholds: skip OC curves, report Youden comparison at single operating point. Document as threshold kill condition triggered.
   - Expected output: `outputs/figures/oc_curves_{scanner}.png`, `outputs/analysis/oc_curve_data.csv`

5. **Statistical comparison**
   - Pairwise Fisher's exact test for detection rate differences (per category and overall)
   - Bonferroni correction for multiple comparisons
   - Cohen's kappa (pairwise) and Fleiss' kappa (multi-scanner) for inter-scanner agreement
   - Effect size: Youden Index difference between scanner pairs
   - Expected output: `outputs/analysis/statistical_tests.csv`

6. **Sensitivity analyses (ablation plan)**
   - Ablation 1: Remove LLM-judge scanners, recompute with rule-based only
   - Ablation 2: Aggregate categories to binary (vulnerable/safe), compare scanner rankings
   - Ablation 3: Exclude known-safe cases (TP/FN only), measure impact on Youden
   - Ablation 4: Strict vs lenient labeling, measure ranking stability
   - Independence assumption test (H-3): clustered bootstrap (server-level resampling) vs standard bootstrap, compare detection rate estimates
   - Expected output: `outputs/analysis/ablation_results.md`

### Phase 3b: AOQL and Scanner Complementarity (CONDITIONAL)

**Activation condition:** Corpus size >=20 AND per-scanner detection rates estimable with CI width < 0.3

1. **AOQL computation**
   - For each scanner: compute Average Outgoing Quality Limit — the maximum fraction of vulnerabilities that pass through undetected, across all vulnerability densities
   - Compare AOQL across scanners
   - Expected output: `outputs/analysis/aoql.csv`

2. **Scanner complementarity analysis**
   - For each scanner pair: compute union detection rate (what they catch together vs alone)
   - Compute diminishing returns: does adding a 3rd scanner to the best 2 substantially improve detection?
   - Jaccard similarity between scanner detection sets
   - Expected output: `outputs/analysis/complementarity.csv`

### Dependencies
- Phase 2 corpus completed with >=15 test cases
- All scanners operational from Phase 1

### Verification
- [ ] All scanners run against complete corpus with results recorded
- [ ] Classification CSV complete with no unresolved ambiguous cases
- [ ] Statistical tests completed per ED Statistical Plan (all specified tests executed)
- [ ] Ablation results documented
- [ ] H-3 independence assumption tested
- [ ] If Phase 3b activated: AOQL and complementarity computed

---

## Phase 4: Synthesis + FINDINGS.md Writing

**Host:** Azure (7.7 GiB)

### Tasks

1. **Resolve all hypotheses**
   - H-1 (distinguishability): SUPPORTED/REFUTED/PARTIALLY SUPPORTED with specific evidence
   - H-2 (specialization): SUPPORTED/REFUTED/PARTIALLY SUPPORTED with specific evidence
   - H-3 (independence): SUPPORTED/REFUTED with comparison data
   - H-4 (AOQL, if activated): SUPPORTED/REFUTED with AOQL values
   - Update HYPOTHESIS_REGISTRY.md Resolution Log

2. **Write FINDINGS.md per govML template**
   - All required sections: Abstract, Methods, Results, Novelty Assessment, Cross-Domain Connections, Generalization Analysis, Practitioner Impact, Hostile Baseline Check, Effect Persistence, Boundary Statement, Pre-emptive Criticism
   - 100% claims tagged per CLAIM_STRENGTH_SPEC
   - Minimum 5 quoted passages from primary sources (depth budget)
   - Differentiate from 5+ prior works in Novelty Assessment

3. **Write Generalization Analysis** (explicit per process_changes — G consistently low without this)
   - Explicit failure modes with quantified thresholds: "Results hold for [conditions] but not [conditions]"
   - Multiple structurally diverse conditions: 3+ OWASP categories, 3+ scanner architectures
   - Report Jaccard similarity between scanner detection sets

4. **Hostile Baseline Check**
   - Simulate hostile reviewer: identify 3+ specific criticisms and document responses
   - Must SURVIVE: every criticism addressed with evidence

5. **Fill EXECUTION_PROTOCOL.md**
   - Document runtime deviations, quality gate results, measurement decisions made during execution
   - This must be filled DURING Phases 1-3, not backfilled in Phase 4

6. **Prepare practitioner artifact**
   - Finalize `scripts/score_scanner.sh` with usage documentation
   - Verify corpus is self-contained and runnable
   - Write outputs/README.md with reproduction instructions

### Dependencies
- Phases 1-3 complete with data
- All statistical analyses from Phase 3 complete

### Verification
- [ ] All hypotheses resolved in HYPOTHESIS_REGISTRY.md
- [ ] FINDINGS.md passes govML template check (all required sections present)
- [ ] 100% claims tagged per CLAIM_STRENGTH_SPEC
- [ ] Depth budget met (>=5 quoted passages)
- [ ] Novelty Assessment differentiates from 5+ works
- [ ] Generalization Analysis section present with explicit boundary statement
- [ ] No prohibited language
- [ ] EXECUTION_PROTOCOL.md filled (not empty/stub)

---

## Estimated Source Plan

| Source | Type | Access Method | Priority | Phase Used |
|--------|------|--------------|----------|------------|
| NVD MCP CVEs (30+) | CVE database | NVD API / nvd.nist.gov | HIGH | Phase 1-2 |
| MCPSecBench (AIS2Lab) | Test harness + attack scripts | git clone from GitHub | HIGH | Phase 1-2 |
| AgentSeal scanner | Open-source tool | pip install agentseal | HIGH | Phase 1, 3 |
| Cisco MCP Scanner | Open-source tool | pip install mcpscanner | HIGH | Phase 1, 3 |
| MEDUSA | Open-source tool | pip install medusa-scan | HIGH | Phase 1, 3 |
| Ant Group MCPScan | Open-source tool | git clone from GitHub | MEDIUM | Phase 1, 3 |
| Sigil | Open-source tool | npm install -g sigilsec | MEDIUM | Phase 1, 3 |
| OWASP Agentic AI Top 10 | Taxonomy | owasp.org/www-project-agentic-ai | HIGH | Phase 2 |
| OWASP Benchmark methodology | Methodology reference | owasp.org/www-project-benchmark | MEDIUM | Phase 2, 4 |
| ISO 2859-1 OC curve methodology | Methodology reference | WebSearch for accessible summaries | MEDIUM | Phase 3-4 |
| AgentSeal 1,808-server blog | Empirical data | agentseal.org/blog | MEDIUM | Phase 4 |
| MCP-SafetyBench (arxiv 2512.15163) | Taxonomy reference | arxiv abstract + WebSearch | MEDIUM | Phase 2, 4 |
| Miercom DAST Benchmark 2026 | Methodology reference | miercom.com / WebSearch | LOW | Phase 4 |
| SAST FP rate studies (Ghost, Autonoma) | Calibration anchor | WebSearch | LOW | Phase 4 |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| CVEs lack sufficient detail for test case construction | MEDIUM | HIGH (corpus too small) | Supplement with MCPSecBench attack scripts (17 types). Manually construct test cases from OWASP taxonomy descriptions. Set kill condition at 15 cases. |
| Scanner installation fails (dependency conflicts, version issues) | MEDIUM | MEDIUM (fewer scanners) | Install in isolated virtual environments. Try 5 scanners, need minimum 3. Document installation issues for reproducibility notes. |
| Scanner outputs not mappable to TP/FP/TN/FN | LOW-MEDIUM | HIGH (methodology requires classification) | Fallback: inter-scanner agreement analysis (Cohen's kappa between scanner pairs) without ground-truth accuracy measurement. Still valuable, but weaker contribution. |
| No scanner has configurable thresholds | MEDIUM | MEDIUM (OC curves not possible) | Fallback: Youden Index comparison at fixed operating points. Report as "threshold kill condition triggered." Still novel (first scanner comparison) but weaker methodological contribution. |
| LLM-judge scanner components produce non-reproducible results | MEDIUM | LOW-MEDIUM (adds noise) | 3 runs per test case, majority vote. Report variance as measure of scanner reliability. Flag high-variance scanners. |
| Mac Mini unavailable via Tailscale during execution | LOW | HIGH (scanner execution blocked) | Attempt scanner installation on Azure if memory allows (may work for lighter scanners). Reduce scanner count if necessary. |
| Corpus labeling errors bias results | LOW | MEDIUM (incorrect ground truth) | 20% manual review with kappa measurement. Publish corpus for community validation. Sensitivity analysis with strict vs lenient labeling. |
| Independence assumption violation distorts OC curves | MEDIUM | LOW-MEDIUM (statistical validity concern) | Pre-registered as H-3. Clustered bootstrap sensitivity analysis. Report both independence and clustered estimates. |
| OWASP Agentic AI taxonomy categories too coarse for meaningful per-category analysis | LOW | MEDIUM (category analysis uninformative) | Use MCPSecBench 17-type taxonomy as secondary categorization. Report at both granularity levels. |
| Total corpus size insufficient for AOQL computation (H-4) | MEDIUM | LOW (H-4 is conditional) | H-4 explicitly conditional on corpus size >=20 and CI width < 0.3. If not met, report as "insufficient data for AOQL" — not a failure, just a boundary. |
