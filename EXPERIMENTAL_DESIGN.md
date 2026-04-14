# Experimental Design: Agent Security Scanner Effectiveness via OC Curves

> **Gate:** 0 (must pass before Phase 1 compute)
> **Date:** 2026-04-14
> **Target venue:** arxiv
> **lock_commit:** e8afae3
> **Profile:** security-ml

## Dispatch 2 Predictions (GPL-07)

Before reading stage 0-2 artifacts in depth, I predict:
- **Hypotheses to pre-register:** 4 (primary on scanner distinguishability, auxiliary on independence assumption, secondary on AOQL, secondary on scanner complementarity)
- **Hardest Kill Shot to mitigate:** "Ground-truth corpus too small for per-category OC curves" — because 30 CVEs across 10 OWASP categories means ~3 per category, far below statistical power thresholds
- **Highest-risk ROADMAP phase:** Phase 2 (ground-truth corpus construction) — if CVEs cannot be converted to reproducible scanner-testable cases, the entire methodology collapses

---

## §0 Problem Selection Gate (Gate -1)

| # | Criterion | Answer |
|---|-----------|--------|
| 1 | **Research question** | Do agent security scanners exhibit statistically distinguishable detection effectiveness when evaluated against a common ground-truth vulnerability corpus using Operating Characteristic curve methodology adapted from manufacturing quality assurance? |
| 2 | **Practitioner pain** | Production MCP server operators at companies deploying 5+ agent-connected services who must choose among 9+ security scanners (AgentSeal, Enkrypt AI, Cisco, MEDUSA, Sigil, Ant Group MCPScan, etc.) with zero comparative data. AgentSeal reports 66% of 1,808 servers have findings; Enkrypt AI reports 33% of 1,000 servers have critical issues. These numbers are incomparable — different severity thresholds, different server populations, different vulnerability definitions. Practitioners currently choose scanners based on marketing claims, not measured detection effectiveness. Traditional SAST tools have 40-91% false positive rates when untuned (Ghost Security 2025; Autonoma/Pixee 2025); agent security scanners likely have comparable or worse rates but no one has measured. |
| 3 | **Novel gap** | (a) OWASP Benchmark v1.2 provides the gold standard for traditional SAST/DAST evaluation using Youden Index scoring on 2,740 Java web app test cases — but covers Java web CWEs only, no agent/MCP vulnerability types. (b) MCP-SafetyBench (Xie et al., ICLR 2026, arxiv 2512.15163) benchmarks 20 attack types across 5 domains but evaluates MODEL safety behavior, not SCANNER detection effectiveness. (c) MCPSecBench (AIS2Lab, arxiv 2508.13220) provides 17 attack types across 4 attack surfaces but tests platform vulnerability, not third-party scanner performance. (d) AgentSeal and Enkrypt AI publish self-reported metrics only — no cross-scanner comparison on common ground truth exists. (e) No work applies Operating Characteristic curves or any threshold-independent comparison framework to security scanner evaluation in ANY domain. Searched "operating characteristic curve security scanner" and "AQL agent security" — 0 results. |
| 4 | **Feasibility** | Yes. Open-source scanners are installable (AgentSeal via pip, Cisco MCP Scanner via pip, MEDUSA via pip, MCPScan from GitHub, Sigil via npm). 30+ MCP CVEs from Jan-Feb 2026 provide ground-truth vulnerability data (CVE-2026-5058 CVSS 9.8, CVE-2026-0755 critical, etc.). MCPSecBench provides modular test harness infrastructure. OC curve computation is standard statistics (binomial/Poisson). Mac Mini (48GB, M4 Pro) provides sufficient compute for scanner execution. Azure (7.7 GiB) handles analysis. Single-cycle feasible with EDA-gated methodology. |
| 5 | **Falsifiability** | The hypothesis is falsified if: (a) scanner OC curves are statistically indistinguishable (all scanners perform identically — unlikely but testable via Kolmogorov-Smirnov test on detection probability functions), or (b) the ground-truth corpus proves too small for meaningful OC curve computation (kill condition: <15 classifiable test cases across >=3 OWASP categories), or (c) scanner outputs cannot be reliably mapped to TP/FP/TN/FN classifications (definitional problem dominates — per-case inter-rater agreement kappa < 0.4). |
| 6 | **Data availability** | (1) MCP CVE corpus: 30+ CVEs accessible via NVD API, 43% are exec/shell injection (common pattern enables test case construction). (2) Open-source scanners: AgentSeal, Cisco MCP Scanner, MEDUSA, Ant Group MCPScan, Sigil — all freely installable. (3) MCPSecBench test harness (open-source, GitHub). (4) AgentSeal MCP Security Registry: 800+ scored servers. (5) OWASP Agentic AI Top 10 taxonomy for category mapping. Three critical unknowns require EDA validation: CVE-to-test-case conversion feasibility, scanner output format mappability, scanner threshold configurability. |
| 7 | **Scope boundary** | **Out of scope:** (a) Runtime governance tools (Microsoft AGT) — these enforce policies, not scan for vulnerabilities; comparison with static scanners is a category error. (b) Model safety benchmarking — MCP-SafetyBench and MCPSecBench already cover this. (c) Scanner architecture analysis — we measure WHAT scanners detect, not HOW they detect it. (d) Vulnerability discovery — we evaluate detection of KNOWN vulnerabilities, not finding new ones. (e) Commercial/closed-source scanners (Enkrypt AI, Snyk agent-scan) unless freely accessible during EDA. |
| 8 | **Success criteria** | (a) Ground-truth corpus of >=15 test cases (known-vulnerable + known-safe) across >=3 OWASP Agentic AI categories, with binary ground-truth labels. (b) >=3 scanners evaluated on the complete corpus. (c) Per-scanner detection probability curves (OC curve analog) computed with 95% confidence intervals. (d) Pairwise scanner comparison via area under detection curve or Youden Index with statistical significance (Fisher's exact test, p<0.05). (e) Per-category detection heatmap showing scanner strengths/weaknesses. |
| 9 | **Kill conditions** | (a) **Corpus kill:** Fewer than 15 classifiable test cases constructible from CVEs + MCPSecBench attacks across >=3 OWASP categories. Fallback: aggregate to binary (vulnerable/safe) without per-category analysis. (b) **Scanner kill:** Fewer than 3 scanners produce parseable output on the corpus. Fallback: reduce to pairwise comparison of 2 scanners. (c) **Mapping kill:** Scanner outputs cannot be mapped to TP/FP/TN/FN — inter-rater agreement kappa < 0.4 between automated mapping and manual review on 20% sample. Fallback: shift to inter-scanner agreement analysis (Cohen's kappa between scanner pairs) rather than accuracy analysis. (d) **Threshold kill:** No scanner has configurable thresholds — OC curves collapse to single points. Fallback: use scanner-vs-scanner comparison at fixed operating points (Youden Index only, without threshold-independent OC curves). |
| 10 | **Prior art check** | **Work 1: OWASP Benchmark v1.2** — Central claim: standardized ground-truth test suite enables objective SAST/DAST comparison. Methodology: 2,740 Java test cases with known-vulnerable/known-safe classifications; Youden Index scoring (TPR - FPR). Relevance: direct methodological precedent; we build the agent-security equivalent. Gap: Java web CWEs only, single-point metric (Youden), no agent/MCP coverage. **Work 2: MCP-SafetyBench (ICLR 2026)** — Central claim: LLMs remain vulnerable to multi-turn MCP attacks, with negative defense-success/task-success tradeoff. Methodology: 20 attack types, 5 domains, multi-turn evaluation against real MCP servers. Relevance: taxonomy source for ground-truth categories. Gap: evaluates model behavior, not scanner detection. **Work 3: Miercom DAST Benchmark 2026** — Central claim: independent third-party evaluation reveals significant detection gaps among commercial DAST tools. Methodology: 11 intentionally vulnerable apps, canonical vulnerability list, independent scan execution + self-built validation apps. Relevance: closest methodological analog for independent scanner evaluation. Gap: traditional web apps only, no threshold-independent analysis, vendor-commissioned. **Work 4: AgentSeal 1,808-server scan (2026)** — Central claim: 66% of MCP servers have security findings; 76 contain confirmed malicious payloads. Methodology: 4-layer pipeline (pattern detection, deobfuscation, semantic analysis, LLM judge) + red-teaming with 380+ attack probes. Relevance: largest published MCP scan dataset; provides empirical anchor. Gap: self-reported, no cross-scanner comparison, no FP rate against ground truth. |
| 11 | **Significance** | If answered: practitioners get the first independent, threshold-independent comparison of agent security scanners. They can choose scanners based on measured detection profiles per vulnerability category, not marketing claims. The OC curve framework is reusable — new scanners can be evaluated against the same corpus. If the AOQL analysis succeeds, practitioners learn whether current scanning is "good enough" by manufacturing QA standards or effectively security theater. The methodology (ground-truth corpus + OC curves for scanner evaluation) transfers to any domain with competing detection tools. |
| 12 | **Disconfirming evidence** | Searched for evidence AGAINST the premise that scanner comparison is needed: (a) "agent security scanner comparison already exists" — 0 results. (b) "MCP scanner evaluation benchmark" — 0 scanner-focused benchmarks found (all model-focused). (c) "agent security scanners all equivalent" — no evidence of equivalence or comparison. (d) "OWASP Benchmark agent security" — no agent-security extension found. (e) Searched for evidence that OC curves are inappropriate for binary detection systems: found that OC curves require varying quality levels to trace the curve — if all test cases have the same vulnerability density, the curve collapses to a single point. Mitigation: construct corpus with graduated vulnerability density (some servers with 1 vuln, some with 3+, some with 0). **Null result:** no disconfirming evidence that the comparison is unneeded; found one methodological constraint (graduated density requirement) that informs corpus design. |
| 13 | **Time-to-outcome feasibility** | Primary outcome (scanner OC curves) measurable within 1 research cycle (~1 week of compute + analysis). EDA phase (2-3 days) validates data assumptions. Scanner execution (1-2 days on Mac Mini). Analysis + writing (2-3 days on Azure). Total: 5-8 days. No long-term outcome delay — results are immediately actionable. |

**Gate -1 verdict:** PASS (pending EDA validation of 3 critical unknowns)

### Assumption Challenge (A8)

The field currently believes that **scanner proliferation improves practitioner security posture** — that having 9+ agent security scanners available means practitioners are better protected. This assumption is embedded in scanner vendor marketing (AgentSeal: "We scanned 1,808 servers"; Enkrypt AI: "33% had critical vulnerabilities") and in community discourse that treats scanner availability as progress. The specific reason this may be incorrect: traditional SAST tools have 40-91% false positive rates when untuned (Ghost Security 2025 across ~3,000 repos; Autonoma/Pixee 2025 on benchmark applications). If agent security scanners have comparable FP rates — plausible given the less mature threat taxonomy (OWASP Agentic AI risks vs well-defined CWEs) — then running unvalidated scanners may degrade security posture by consuming team bandwidth on false alerts while creating false confidence. The 66% vs 33% divergence between AgentSeal and Enkrypt AI already suggests calibration is poor. More scanners without calibration may mean more noise, not more signal.

### Artifact-first design

The primary practitioner artifact is a **benchmark corpus + scoring framework** — a downloadable test suite of MCP server configurations with known-vulnerable and known-safe labels, plus a scoring script that runs any scanner against the corpus and computes detection metrics (Youden Index, OC curve data points, per-category heatmap). Secondary artifact: a comparative scorecard (CSV/JSON) of evaluated scanners' detection profiles. This is the agent-security equivalent of the OWASP Benchmark test suite. A practitioner can run `./score_scanner.sh <scanner_command>` against the corpus and get a detection profile in 15 minutes.

### Surprise pre-registration

**Expected finding:** Scanners will show moderate disagreement, with each scanner showing strengths in different vulnerability categories (specialization pattern). Some scanners will perform near-random on categories outside their design focus.

**Genuine surprise:** (a) If ALL scanners perform near-random (Youden < 0.1) on ALL categories — this would mean current agent security scanning is effectively theater. (b) If ONE scanner dominates across ALL categories — this would mean the field has already converged on a solution and the other 8+ scanners are redundant. (c) If scanner agreement is high but accuracy against ground truth is low — this would mean scanners share the same blind spots (systematic bias, not independent noise). Any of these would surprise both scanner developers and the security research community.

### Cross-domain bridge

**Manufacturing quality assurance** faces the analogous problem of comparing inspection systems (scanners) that accept/reject manufactured lots (MCP servers) with varying defect rates (vulnerability densities). ISO 2859-1 provides the formal framework: Operating Characteristic curves plot acceptance probability vs true defect fraction, quantifying producer risk (false positives) and consumer risk (false negatives). The specific parallel: choosing between inspection vendors in manufacturing (each claims high quality, none provides comparable data) maps exactly to choosing between security scanners (each claims effectiveness, none provides comparable data). The OC curve framework resolved this in manufacturing decades ago.

### Scope Restriction Impact Assessment

| Restriction | Why Imposed | Estimated Dimension Impact | Mitigation |
|---|---|---|---|
| Exclude runtime governance tools (Microsoft AGT) | Category error — policy enforcement vs vulnerability scanning | G: -0.5 (narrower tool coverage) | Acknowledge as boundary; note AGT comparison as future work |
| Open-source scanners only | Reproducibility + single-cycle feasibility | G: -0.5 (excludes enterprise tools); R: +0.5 (full reproducibility) | List excluded tools; provide framework for future extension |
| CVE-based ground truth (not live honeypots) | Controlled experiment > ecological validity | G: -0.5 (lab vs real-world); R: +1.0 (known ground truth) | Acknowledge ecological validity threat; recommend honeypot follow-up |
| >=3 OWASP categories (not all 10) | Statistical power with ~30 CVEs | N: -0.3 (less comprehensive); R: +0.5 (adequate power per category) | Report which categories excluded and why |

---

## §1 Project Identity

- **Title:** Agent Security Scanner Operating Characteristics: A Manufacturing QA Framework for Comparative Evaluation
- **Target venue:** arxiv (cs.CR + cs.SE cross-list)
- **Lock commit:** TBD (set on commit of this file)
- **Research type:** computational
- **Domain:** AI security — agent security tooling evaluation

---

## §2 Novelty Claim

First threshold-independent comparison of agent security scanners using manufacturing QA Operating Characteristic curves on common ground-truth MCP vulnerability corpus.

---

## §3 Comparison Baselines

| # | Baseline | Source | What it covers | What it misses |
|---|----------|--------|---------------|----------------|
| 1 | OWASP Benchmark v1.2 Youden Index scoring | owasp.org/www-project-benchmark | Ground-truth test suite (2,740 cases) with TPR-FPR scoring for Java SAST/DAST tools. Gold standard for traditional scanner evaluation. | Agent/MCP vulnerabilities (Java CWEs only). Threshold-independent comparison (Youden is single-point). No OC curves. |
| 2 | Miercom DAST Benchmark 2026 | miercom.com | Independent evaluation of DAST tools on 11 intentionally vulnerable apps with detection accuracy measurement. Self-built validation apps for cross-validation. | Agent/MCP vulnerabilities (traditional web apps only). No threshold-independent analysis. Vendor-commissioned (Invicti). |
| 3 | AgentSeal self-reported metrics | agentseal.org/blog | Largest published MCP scan (1,808 servers). 66% findings rate. ~4.2% FP on 120 known-benign servers. Security scores for 800+ servers. | Single-scanner only. Self-reported. No cross-scanner comparison. No per-category detection rates against ground truth. |

---

## §4 Kill Shots

| # | Criticism | Severity | Mitigation | Evidence mitigation works |
|---|-----------|----------|-----------|--------------------------|
| 1 | "Ground-truth corpus is too small (30 CVEs / ~15 usable test cases) for statistically meaningful per-category OC curves." | HIGH | (a) Supplement CVEs with MCPSecBench attack scripts (17 types) and manually constructed test cases from OWASP Agentic AI taxonomy. Target: 30+ test cases. (b) Report per-category results with exact confidence intervals (Clopper-Pearson) rather than point estimates. (c) If categories have <5 cases, aggregate into supercategories (injection-class, access-control-class, data-handling-class). (d) Use Fisher's exact test (valid for small samples) rather than chi-squared. | OWASP Benchmark started with fewer test cases in v1.0 and was still impactful because the FRAMEWORK (ground truth + scoring) was the contribution, not the corpus size. Miercom evaluates on 11 apps — small corpus with careful methodology is accepted practice. |
| 2 | "OC curves are designed for acceptance sampling with lot-based inspection. Security scanners examine 100% of code, not samples. The methodology import is superficial." | HIGH | (a) We use OC curves as detection probability curves — plotting P(detect) vs true vulnerability density. The mathematical form (probability vs quality level) is identical; the generating process differs. (b) We explicitly acknowledge in LA §6b.1 that the SAMPLING aspect does not transfer but the DETECTION PROBABILITY CHARACTERIZATION does. (c) A quality engineer would recognize the curve shapes and their interpretation (steep = discriminating, flat = unreliable) regardless of whether the underlying process involves sampling. (d) We complement with Youden Index (the traditional security metric) so results are interpretable in both frameworks. | The ROC curve originated in signal detection theory (radar) and was imported to medicine, psychology, and machine learning — each application adapted the framework to non-radar contexts. OC curves imported to security scanner evaluation follows the same pattern of framework transfer with domain adaptation. |
| 3 | "Scanner disagreement may be primarily definitional (different vulnerability ontologies), not operational (different detection quality). Your comparison conflates the two." | MEDIUM | (a) Per-category analysis partially decomposes: categories where scanners agree on definitions but disagree on detection reveal operational differences; categories where scanners disagree on what constitutes a finding reveal definitional differences. (b) For the ground-truth corpus, WE define the correct answer — the ground truth establishes a shared ontology for evaluation purposes. Scanners that disagree with the ground truth on what is a vulnerability get scored as FP or FN. (c) Report inter-scanner agreement (Cohen's kappa) alongside accuracy metrics to quantify definitional vs operational disagreement. | OWASP Benchmark faces the same challenge (different SAST tools have different CWE coverage) and resolves it by providing the ground truth definition. Our approach follows the same pattern. |
| 4 | "Results are not generalizable beyond the specific CVEs and scanners tested." | MEDIUM | (a) Design corpus to cover >=3 structurally diverse OWASP categories. (b) Include scanners with diverse architectures (rule-based, LLM-judge, taint analysis). (c) Report explicit boundary statement: "These results apply to the tested scanners on the tested corpus as of April 2026." (d) Publish the corpus and scoring framework so results can be updated as scanners evolve. (e) Compute Jaccard similarity between scanner detection sets to measure structural diversity of scanner behavior. | Prior cycle G=7 was achieved with 3 structurally diverse conditions (Cycle 3: 3 graph sizes, Jaccard 0.61-0.82). We target 3+ OWASP categories and 3+ scanner architectures. |

### §4a Constraint-Driven Design Check

| Constraint | Source | How it shaped design |
|---|---|---|
| CVE corpus size (~30 raw, ~15-30 usable test cases) | LA §6 EDA Readiness | Chose Fisher's exact test over chi-squared (valid for small N). Designed supercategory aggregation as fallback. Set kill condition at 15 cases. |
| Scanner threshold configurability unknown | LA §6 Data Source Sample Verification | Designed EDA Phase 1 to test threshold configurability before committing to full OC curve methodology. Fallback: Youden-only comparison at fixed operating points. |
| Independence assumption violation for OC curves | LA §6b.1 Mechanism Validity | Pre-registered as auxiliary hypothesis (H-3). Planned sensitivity analysis: compare OC curves computed under independence vs correlated-defect assumptions. |
| Mac Mini compute for scanner execution | Compute resources query | Routed scanner installation and execution to Mac Mini (48GB). Azure handles analysis only. |
| Contested vulnerability definitions | LA §3 Baseline Knowledge State | Ground-truth corpus defines the correct answer, resolving definitional ambiguity for evaluation purposes. Report inter-rater kappa on 20% manual review sample. |

### Related Work

The landscape of agent security evaluation contains three MCP benchmarks (MCP-SafetyBench, MSB, MCPSecBench) that all evaluate model/agent behavior against attacks, not scanner detection effectiveness. The traditional AppSec domain provides two methodological precedents: OWASP Benchmark (ground-truth test suite + Youden scoring) and Miercom DAST Benchmark (independent scanner evaluation on intentionally vulnerable apps). No work bridges these traditions to agent security scanner evaluation, and no work in any security domain applies threshold-independent comparison frameworks (OC curves from manufacturing QA). Our work fills this dual gap: domain transfer (web app evaluation methodology to agent security) and method import (OC curves from ISO 2859-1 to security tool evaluation).

### Threats to Validity

| Threat | Type | Mitigation |
|--------|------|-----------|
| Ground-truth corpus may not represent real-world vulnerability distribution — CVEs over-represent discoverable vulns, under-represent subtle design flaws | External validity | Supplement CVEs with MCPSecBench attack scripts and OWASP taxonomy-driven synthetic cases. Report corpus composition transparently. Acknowledge as boundary: "Results reflect detection of KNOWN vulnerability patterns, not zero-day discovery." |
| LLM-as-judge scanner components (AgentSeal, Cisco, MCPScan) produce stochastic results — scanner output may differ across runs | Reliability | Run each scanner 3 times per test case. Report result variance. Use majority-vote classification for non-deterministic scanners. Flag scanners with high variance as unreliable. |
| Researcher-constructed ground truth may contain labeling errors — we are not MCP security domain experts | Construct validity | Cross-validate labels against CVE descriptions, CVSS scores, and public exploit availability. Conduct 20% sample manual review with inter-rater agreement measurement (target kappa > 0.6). Publish corpus with labels for community validation. |
| OC curve independence assumption violated by correlated vulnerabilities within MCP servers | Internal validity | Pre-registered as auxiliary hypothesis (H-3). Sensitivity analysis: compare results under independence assumption vs clustered-vulnerability model. Report both. |

### Statistical Plan (MANDATORY for computational research)

| Parameter | Value | Justification |
|-----------|-------|---------------|
| Primary test | Fisher's exact test (pairwise scanner comparison per category) | Valid for small sample sizes (N < 30 per category). Tests whether detection rates differ significantly between scanner pairs. |
| Significance threshold (alpha) | 0.05 | Standard. |
| Multiple comparison correction | Bonferroni correction across all pairwise comparisons | With 3 scanners and 3+ categories, expect ~9+ comparisons. Bonferroni corrected alpha = 0.05/K. |
| Effect size metric | Youden Index (TPR - FPR) per scanner per category; area under detection probability curve (AUC analog) for threshold-independent comparison | Youden enables comparison with OWASP Benchmark tradition. AUC enables threshold-independent comparison. |
| Confidence intervals | Clopper-Pearson exact binomial 95% CI on detection rates | Appropriate for small-sample proportions. |
| Minimum sample size per category | 5 test cases (below this, category results are reported descriptively, not inferentially) | Fisher's exact test is valid at N=5 but power is low. Categories with <5 cases flagged as underpowered. |
| Inter-scanner agreement | Cohen's kappa (pairwise) and Fleiss' kappa (multi-scanner) | Measures both definitional and operational agreement. Kappa < 0.4 = poor agreement, 0.4-0.6 = moderate, >0.6 = substantial. |
| Seeds/runs | 3 runs per scanner per test case (for stochastic scanners) | Captures LLM-judge variance. Deterministic scanners: 1 run sufficient. |

### Ablation Plan (MANDATORY for computational research)

| Component | Hypothesis When Changed | Expected Effect |
|-----------|------------------------|-----------------|
| Remove LLM-judge scanners (keep rule-based only) | LLM-judge scanners contribute detection of semantically subtle vulnerabilities that rule-based scanners miss | Detection rates drop for "tool poisoning" and "prompt injection" categories (semantic); stable for "code injection" (syntactic) |
| Aggregate categories into binary (vulnerable/safe) | Per-category analysis reveals specialization patterns that aggregate analysis hides | Scanner ranking changes — a scanner that is best at injection but worst at data exfiltration may rank differently in aggregate vs per-category |
| Exclude known-safe test cases (TP/FN only, no FP/TN) | False positive rates differ substantially across scanners and are the primary practitioner concern (alert fatigue) | Youden Index changes significantly; scanners with high TPR but also high FPR lose their apparent advantage |
| Vary ground-truth labeling threshold (strict vs lenient) | Sensitivity analysis for labeling subjectivity — strict labels (only confirmed RCE/injection) vs lenient (includes misconfigurations) | Scanner accuracy scores shift; some scanners may perform better under lenient labeling (they detect misconfigs that strict labeling excludes) |

### Audience Alignment
- **Audience:** Production agent/MCP operators choosing security scanners; agent security researchers building evaluation methodology; scanner developers seeking independent validation data
- **Portfolio position:** Extends pipeline's agent security program (Cycles 1, 7, 8) from vulnerability taxonomy and contagion modeling to empirical tool evaluation — the measurement layer that was missing
- **Distribution plan:** arxiv (cs.CR + cs.SE cross-list); benchmark corpus published as GitHub repo; scoring framework as pip-installable CLI tool; summary post for practitioner channels (DEV Community, r/netsec)

### Adaptive Adversary Analysis (MANDATORY for security-domain projects)

**How would a motivated adversary exploit the findings?**

(a) An adversary who learns which vulnerability categories each scanner misses could craft MCP servers that exploit specifically those blind spots — publishing a "safe-looking" server that passes the most popular scanner while containing vulnerabilities in its weak categories. This is the "teaching to the test" problem: publishing scanner detection profiles enables targeted evasion.

(b) If the benchmark corpus becomes widely used, adversaries could study the specific test cases and craft vulnerabilities that differ just enough to evade detection while being structurally similar — mutation-based evasion.

**Which blind spots are most dangerous?**

The most dangerous blind spot is a vulnerability category where ALL scanners show low detection AND the category has high real-world prevalence. If e.g., "data exfiltration via MCP tool responses" is both common and universally undetected, that is an actionable gap for adversaries.

**Responsible disclosure approach:**

(a) Do not publish specific evasion techniques derived from scanner blind spots. (b) Report vulnerability categories with low detection rates in aggregate (e.g., "Category X has <30% detection across all tested scanners") without providing specific bypass patterns. (c) Notify scanner vendors of category-level blind spots before public release (30-day window). (d) Publish the benchmark corpus (which contains known, already-public vulnerabilities from CVEs) — this is not new vulnerability disclosure.

---
