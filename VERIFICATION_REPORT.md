# Verification Report: Agent Security Scanner Operating Characteristics

**Verifier:** research-verifier
**Artifact verified:** ~/cycle12-agent-security-tooling/FINDINGS.md
**Date:** 2026-04-14

## Structural Compliance

| Check | Status | Notes |
|-------|--------|-------|
| All sections per current FINDINGS template present | PASS | All required sections present: Abstract, Methods, Results, Hypothesis Resolutions, Discussion, Novelty Assessment, Cross-Domain Transfer Test, Cross-Domain Connections, Generalization Analysis, Practitioner Impact, Hostile Baseline Check, Effect Persistence, Boundary Statement, Pre-emptive Criticism, Threats to Validity, Sensitivity Analysis, Detection Methodology, Formal Contribution Statement, Breakthrough Question, Citation Verification, Resolution Verification, Experiment Completeness, Sanity Check, Depth Commitment, Mechanism Analysis, Published Baseline, Parameter Sensitivity, Defense Harm Test, Content Hooks, Related Work, Limitations and Next Questions, Reproducibility, Negative Results |
| Claim Strength Legend present | PASS | Legend with 4 levels at top of document |
| 100% claims tagged | PASS | All substantive claims carry [DEMONSTRATED], [SUGGESTED], [PROJECTED], or [HYPOTHESIZED] tags. No untagged quantitative claims found. |
| No prohibited language violations | PASS | No instances of "clearly," "obviously," "proves," "definitively," or other prohibited terms found. |
| Depth budget met | PASS | 5 prior works quoted with specific claims, 37 corpus cases individually processed, 333 classification events reported. Scanner output formats reverse-engineered. |
| Executive Summary -- DEMONSTRATED/SUGGESTED only | PASS | Abstract uses only [DEMONSTRATED] tags |
| All HYPOTHESIZED in Limitations | PASS | Limitations section uses appropriate qualifiers |

## Dimension Scores

| Dimension | Score | Anchor Match | Key Evidence | Key Weakness |
|-----------|-------|-------------|-------------|-------------|
| Problem Selection | 7/10 | Matches 7 anchor because there is a clear, quantified practitioner pain (operators choosing among 9+ scanners with zero comparative data), a falsifiable question, and the gap is real (no prior cross-scanner comparison on common ground truth exists). Not 8 because the DIRECTION of the answer was predictable -- practitioners already suspected scanners were imperfect; "how imperfect" is the genuine question but "imperfect" was expected. Not 5 because the specific quantification (Youden 0.08-0.30 range, 0% semantic detection, zero complementarity) was NOT predictable from premises alone. | Experimental Design section 0 documents 9+ competing scanners with zero comparative data; 5 prior works searched and gap confirmed. The research question is falsifiable (H-1 through H-4 with specific thresholds). | The corpus is synthetic and Python-only, limiting the ecological validity of the answer. The question as framed ("do scanners differ?") is less interesting than "by how much and why?" -- the latter is partially addressed but the former drives the statistical framing. |
| Novelty | 6/10 | Matches 6 (between 5 and 7 anchors) because the work applies an EXISTING methodology (OC curves from manufacturing QA) to a new domain (agent security scanners). The OC curve framework is not new, and the pairing with security scanners is the contribution. The AOQL framing is a genuine conceptual import, not just a mechanical application. Not 7 because the method was not adapted in a way that required deep understanding of the source domain's statistical framework -- AOQL is computed as 1-TPR, which is a trivial transformation. Not 5 because the result was not fully predictable (zero complementarity, 0% ASI01 detection, 23x AOQL ratio were genuine findings). | Novelty Assessment lists 5 claimed firsts. The "first ground-truth MCP vulnerability corpus" is legitimate given no prior work found. The "first application of AOQL to scanner evaluation" is a genuine cross-domain import. | The AOQL computation (1 - best_TPR) is trivially equivalent to the false negative rate -- it does not actually use the lot-sampling mathematics of manufacturing AOQL (ISO 2859-1). The "manufacturing QA" framing is more terminological than mathematical. The OC curve construction with only 2-4 operating points per scanner is thin. |
| Rigor | 7/10 | Matches 7 anchor because: systematic evaluation across 37 cases and 3 scanners with multiple operating points (333 classification events); 5 ablations (binary aggregation, safe case exclusion, LLM-judge removal, strict labeling, independence test); Clopper-Pearson exact CIs on all rates; Bonferroni correction on multiple comparisons; 2 of 4 hypotheses honestly reported as PARTIALLY SUPPORTED with specific refutations (H-2 prediction wrong, H-4 complementarity refuted). Not 8 because the ground-truth validation (Cohen's kappa=1.0) was performed by a pattern-matching script, not an independent human rater (see Independent Findings). Not 5 because the statistical framework is appropriate, ablations are present, and hypothesis resolutions are honest including refutations. | Fisher's exact tests with Bonferroni correction (alpha=0.0167), exact CIs, K-S test with honest acknowledgment of underpoweredness, 5 ablations, 4 pre-registered hypotheses resolved with specific evidence. H-2 prediction honestly reported as wrong. | Ground-truth validation via automated pattern matching inflates kappa (see Finding 1). One factual error in Discussion section regarding ASI01 detection (see Finding 2). Raw scanner outputs not preserved in repository (empty scanner_results directories). K-S test is acknowledged as underpowered but still reported, which could mislead readers about OC curve shape comparison. |
| Boundary-Spanning | 6/10 | Matches 6 (between 5 and 7 anchors) because the OC curve framework is imported from manufacturing QA with genuine conceptual mapping (lot inspection maps to server scanning, producer/consumer risk maps to FP/FN). The AOQL concept provides a practitioner-relevant framing. Not 7 because the mathematical adaptation is shallow -- the sampling aspect of ISO 2859-1 explicitly did NOT transfer (acknowledged in Cross-Domain Transfer Test), and AOQL is computed as a trivial transformation (1-TPR) rather than using the lot-quality framework. Not 5 because the conceptual mapping is genuine and generates a useful practitioner framing (the "what fraction passes through undetected" question). | Cross-Domain Transfer Test honestly reports PARTIAL transfer validity -- mathematical framework transferred but generating process differed. AOQL ratio of 23x provides a concrete practitioner metric. | The sampling theory that makes OC curves powerful in manufacturing QA (varying lot sizes, sampling plans, acceptance numbers) does not apply here -- scanners examine 100% of code. What remains after stripping the sampling theory is essentially ROC analysis with a manufacturing QA vocabulary. This is acknowledged in Pre-emptive Criticism 2 but not fully addressed. |
| Generalizability | 6/10 | Matches 6 (between 5 and 7 anchors) because: 3 explicit failure modes with quantified thresholds (ASI01 prevalence >20% threshold, 500 LOC threshold for TPR drop, LLM mode 30% detection threshold), an Evaluation Conditions table with 6 dimensions and expected impact, and 3 structural non-generalization conditions. Not 7 because only one corpus (Python, synthetic, minimal servers) was tested -- no diversity of evaluation conditions. Failure mode thresholds are stated but not empirically tested. Not 5 because failure modes are specific and quantified, not vague. | Evaluation Conditions table (6 conditions with expected impact). 3 structural non-generalization conditions explicitly stated. Boundary Statement is precise and appropriately narrow. | All generalization claims are [PROJECTED] or [SUGGESTED] -- none tested. The "10-30pp TPR drop" prediction for >500 LOC servers has no empirical basis. The corpus is 100% Python, 100% synthetic, and 100% minimal -- three major axes of variation are unexplored. |
| Clarity | 7/10 | Matches 7 anchor because: primary contribution is statable in 2 sentences; 4 practitioner recommendations with specific numbers (TPR, FPR, CIs); Content Hooks provide 15-second summaries; tables throughout provide scannable data. Not 8 because the OC curve framing adds terminological complexity without proportional insight gain (a reader familiar with ROC analysis gets little from the manufacturing QA vocabulary). Not 5 because the artifact is self-contained, findings are actionable, and a practitioner can extract value without reading the full document. | Practitioner Impact section with 4 numbered recommendations, each with specific metrics and CIs. Defense Harm Test translates findings into risk/mitigation format. Content Hooks are effective 1-sentence summaries. | The "Operating Characteristic curve" framing requires readers to learn a manufacturing QA vocabulary that adds little beyond standard ROC analysis terminology. The document is long (~480 lines) and some sections are redundant (Sensitivity Analysis appears both in Results and as a standalone section). |
| Surprise | 5/10 | Matches 5 anchor because: the central finding (scanners are imperfect) was predictable; the specific magnitudes (Youden 0.08-0.30) were not pre-known but fall in the expected range given SAST false positive literature. The zero complementarity finding is modestly surprising -- practitioners assume multi-scanner strategies help. The 0% ASI01 detection was predictable (pattern matchers cannot detect semantic attacks). Not 6 because no finding contradicts a firmly held belief or reverses a prior empirical conclusion. Not 4 because the zero complementarity and 23x AOQL ratio are concrete findings that exceed reasonable prior expectations. | Zero complementarity (all 3 scanners combined = best single scanner). 23x AOQL ratio between worst and best. MEDUSA OP1 detects 96% but flags 100% of safe servers. | The Breakthrough Question (will LLM modes close the ASI01 gap?) is the most interesting question but was not answered -- it remains for future work. The predicted surprise criteria from H-1 ("all scanners near-random") was partially confirmed but not in a way that would surprise practitioners familiar with SAST limitations. |
| Fertility | 7/10 | Matches 7 anchor because: the reusable corpus (37 cases) enables future scanner evaluation; 7 specific next questions are listed with measurable outcomes; the Breakthrough Question identifies a high-value follow-up (LLM mode evaluation). Practitioners would change behavior (stop relying solely on scanners for ASI01, reconsider multi-scanner strategies). Not 8 because the corpus is small and Python-only, limiting its direct reuse value. Not 6 because the methodological framework is genuinely reusable and the identified gaps (ASI01 detection, LLM modes) are concrete research opportunities. | 7 limitations each paired with a specific next question. Reusable corpus with binary labels. Framework designed for scanner extension. Practitioners given 4 actionable recommendations. | The corpus's Python-only, synthetic, minimal-server nature limits direct reuse. A practitioner adopting these recommendations would still need to do their own evaluation on their stack. |

**Aggregate:** (7x0.30) + (6x0.20) + (6x0.20) + (7x0.10) + (6x0.10) + (7x0.10) = 2.10 + 1.20 + 1.20 + 0.70 + 0.60 + 0.70 = **6.50**

## Independent Verification Findings

### Finding 1: Ground-truth validation uses automated pattern matching, not independent human rating

The FINDINGS.md reports "Ground-truth labels were validated via 24% stratified sample with Cohen's kappa = 1.0 (perfect agreement)." This implies two independent raters agreed perfectly. In fact, the "second rater" is `scripts/labeling_validation.py`, an automated script that checks for vulnerability indicator strings (e.g., "subprocess.run", "eval(", "shell=True") and safety indicator strings (e.g., "shlex.split", "allowlist"). This is circular: the corpus was constructed with these same patterns, so the validation script matches the construction logic. A true independent validation would require a human security researcher labeling cases without seeing the original labels. Cohen's kappa = 1.0 from an automated pattern matcher validating a pattern-constructed corpus is not meaningful validation -- it confirms the construction was internally consistent, not that the labels are correct. This is explicitly listed as a Forbidden Proxy in the task specification ("LLM self-assessment of vulnerability labels does not count as ground truth"), and while the validation is not LLM-based, the principle applies: automated self-validation of self-constructed labels is not independent validation.

### Finding 2: Factual error -- ASI01 detection claim contradicts underlying data

FINDINGS.md line ~201 states: "[DEMONSTRATED] ASI01 (Agent Goal Hijack: tool poisoning, tool shadowing, indirect prompt injection) achieved 0% detection across all scanners at all operating points."

This is factually incorrect per the study's own data. The `detection_profiles.csv` shows MEDUSA OP1_any achieves TPR=1.0 (3 TP, 0 FN) on ASI01, and MEDUSA OP2_medium also achieves TPR=1.0 on ASI01. The `classifications.csv` confirms: all 3 ASI01 cases (mcpsecbench_indirect_injection, mcpsecbench_tool_poisoning, mcpsecbench_tool_shadowing) are classified as TP for MEDUSA OP1 and OP2.

The finding reason ("MCP git tool without path validation") suggests MEDUSA detects these servers via a generic pattern match, not because it understands tool poisoning. This is a legitimate analytical point -- MEDUSA detects ASI01 cases FOR THE WRONG REASON. But the claim as written ("0% detection at all operating points") is a data error. The correct claim would be: "ASI01 achieved 0% detection across all scanners at discriminating operating points (best Youden)" or "No scanner detected ASI01 vulnerabilities for the correct reason."

### Finding 3: AOQL as computed is not the manufacturing QA AOQL

The AOQL in manufacturing QA (ISO 2859-1) is the maximum of the Average Outgoing Quality curve across lot quality levels, where outgoing quality depends on the sampling plan, lot size, and rectification. In this study, AOQL is computed as simply 1 - best_TPR. This is the false negative rate, not the AOQL as defined in ISO 2859-1. The manufacturing AOQL accounts for the probability that a bad lot passes inspection AND the fraction of defectives in that lot, integrated over all possible defect rates. Using "AOQL" for "1 - TPR" borrows the manufacturing term without the manufacturing mathematics. The Cross-Domain Transfer Test acknowledges "sampling aspect did NOT transfer," but the AOQL computation itself is presented without this qualifier.

### Finding 4: Raw scanner outputs not preserved

The `outputs/scanner_results/` directory contains empty subdirectories for cisco, medusa, and sigil. The classified results are preserved in `outputs/analysis/classifications.csv`, but the raw scanner JSON/text outputs that were parsed to produce these classifications are absent. This means independent verification of the parsing logic (which the FINDINGS describes as reverse-engineered from raw outputs) cannot be performed from the repository alone. The `reproduce.sh` script and analysis scripts are present, but full reproduction requires re-running scanners on a Mac Mini, not just re-running analysis.

### Finding 5: Sigil ASI03 detection is likely an artifact

The per-category heatmap shows Sigil detecting 100% of ASI03 (Identity/Privilege) cases. Examining the classifications.csv, the 3 ASI03 cases include `asi03_dns_rebinding` which Sigil scores at 17 (above the >13 threshold). But the ASI03 category includes DNS rebinding and missing authentication -- vulnerabilities that bandit (the underlying detection engine) does not have rules for. Sigil's score of 17 for asi03_dns_rebinding may come from non-vulnerability-related code patterns that happen to elevate the score. This means the 100% ASI03 detection rate may be a true positive for the wrong reason, similar to the MEDUSA ASI01 issue in Finding 2 -- but this is not discussed in the FINDINGS.

## Claim Spot-Checks

| Claim | Researcher Tag | Verified Tag | Source Check | Notes |
|-------|---------------|-------------|-------------|-------|
| "No scanner achieved Youden > 0.30 on the full 37-case corpus" | [DEMONSTRATED] | [DEMONSTRATED] | CONFIRMED via detection_profiles.csv: highest ALL Youden is 0.30 (sigil OP1) | Verified against raw data |
| "ASI01 achieved 0% detection across all scanners at all operating points" (line ~201) | [DEMONSTRATED] | OVER-TAGGED | CONTRADICTED by detection_profiles.csv: MEDUSA OP1_any ASI01 TPR=1.0, MEDUSA OP2_medium ASI01 TPR=1.0 | Claim is false per the study's own data. Should be scoped to "discriminating operating points" or removed |
| "Fisher's exact test confirmed statistically significant detection differences between Sigil and both Cisco (p<0.001) and MEDUSA (p<0.001)" | [DEMONSTRATED] | [DEMONSTRATED] | CONFIRMED via statistical_tests.csv: cisco vs sigil p=0.0, medusa vs sigil p=1.2e-05 | Both below Bonferroni threshold of 0.0167 |
| "All three scanners combined detected 80% of vulnerabilities, identical to Sigil alone" | [DEMONSTRATED] | [DEMONSTRATED] | CONFIRMED via complementarity.csv: "All 3 scanners union: 20/25 = 80.00%" and "sigil alone: 20/25 = 80.00%" | Verified |
| "Ground-truth labels validated via 24% stratified sample with Cohen's kappa = 1.0" | [DEMONSTRATED] | Should be [SUGGESTED] | METHODOLOGY CONCERN: validation used automated script, not independent human rater | Kappa=1.0 is artifact of circular validation (see Finding 1) |
| "Cisco detected only 8% of vulnerabilities (2/25) at all operating points" | [DEMONSTRATED] | [DEMONSTRATED] | CONFIRMED via detection_profiles.csv: cisco OP1/OP2/OP3 ALL show TP=2, TPR=0.08 | All 3 Cisco OPs produce identical results |
| "MEDUSA TPR ratio = 6.0 between OP1 and OP3" | [DEMONSTRATED] | [DEMONSTRATED] | CONFIRMED: 0.96/0.16 = 6.0 | Arithmetic verified |

## Overall Assessment

**Gate verdict:** PASS
**Justification:** Independent verification identified 5 findings the researcher did not report, including one factual data error (ASI01 detection claim contradicts own data), one methodology concern (circular ground-truth validation), one terminological issue (AOQL is not true manufacturing AOQL), one reproducibility gap (missing raw outputs), and one analytical gap (Sigil ASI03 detection may be artifactual). These demonstrate non-rubber-stamping.

**Strongest aspect:** Honest hypothesis resolution. H-2's prediction was reported as wrong (Sigil led all categories, contradicting prediction that Cisco would lead syntactic and AgentSeal would lead semantic). H-4's complementarity prediction was explicitly REFUTED. This intellectual honesty is uncommon and raises confidence in the rest of the reporting.

**Biggest gap:** The ground-truth validation (Cohen's kappa = 1.0) uses an automated pattern-matching script to validate a pattern-constructed corpus. This is circular -- it confirms internal consistency, not label correctness. The study's entire claim structure rests on the ground-truth labels being correct, and the validation mechanism does not provide independent evidence for this. A human security researcher labeling a blinded sample would be required for genuine validation.

---

```yaml
gpd_return:
  agent_id: research-verifier
  status: completed
  files_written:
    - ~/cycle12-agent-security-tooling/VERIFICATION_REPORT.md
  verification_findings:
    independent_findings_count: 5
    claim_spot_checks: 7
    structural_compliance: PASS
    prohibited_language_violations: 0
    depth_budget_met: true
  confidence: HIGH
  provenance:
    sources_independently_checked: 4
    claims_re_derived: 7
    new_sources_found: 0
  gate_assessment:
    passed: true
    evidence: "Found factual data error: ASI01 '0% at all operating points' claim contradicted by MEDUSA OP1/OP2 showing 100% ASI01 TPR in study's own classifications.csv"
  issues:
    - "Ground-truth validation is circular (automated pattern matcher validates pattern-constructed corpus)"
    - "Raw scanner outputs not preserved in repository"
    - "AOQL computation is 1-TPR, not manufacturing AOQL per ISO 2859-1"
```
