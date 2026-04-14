# RESEARCH QUESTION SPEC

<!-- version: 0.1 -->
<!-- created: 2026-04-14 -->
<!-- stage: 1 -->
<!-- methodology_status: partial — stages 0-2 methodology from Phase B.1 -->

> **Purpose:** Force question formation from observations, not from intuition alone.
> Prevent "I want to study X" without "here's the gap that makes X worth studying."
> This template defines WHAT to document about a research question, not HOW to
> formulate one. The middle loop discovers process.

## Prediction (GPL-07)

Before formulating, I predict question framing around **scanner effectiveness measurement using cross-domain statistical methods** will score highest on §4.2 novelty pre-mortem. Rationale:

- A pure "survey which scanners exist" framing would be PREDICTABLE (the answer is a list, no surprise possible)
- A "build a better scanner" framing would be computational but not novel (9+ already exist)
- A "measure the measurers using manufacturing QA's statistical framework" framing has PARTIALLY PREDICTABLE direction (scanners will disagree) but UNPREDICTABLE magnitude and structure (which threat categories show highest divergence? does calibration via OC curves reveal a scanner that's dominant vs ones that are noise generators?)

I predict the third framing — adapting AQL/OC curve methodology from manufacturing QA to create an OWASP-Benchmark-style evaluation for agent security scanners — will score PARTIALLY PREDICTABLE, with the unpredictable component being whether scanner disagreement is systematic (different tools good at different things) or random (some tools are just noise). This is the framing I will develop.

---

## §0 Question Statement

**Research question:** Do agent security scanners (AgentSeal, Enkrypt AI, Microsoft AGT, and others) exhibit statistically distinguishable detection effectiveness when evaluated against a common ground-truth vulnerability corpus using Operating Characteristic curve methodology adapted from manufacturing quality assurance?

> Traces to OBS-1 (scanner proliferation without measurement), OBS-3 (66% vs 33% divergent findings), OBS-7 (existing benchmarks measure models not scanners).

### §0a Paradigm Challenge — Start Here

<!-- source: Phase I Gap Research (G1+G7), Track 1 (5/7 papers) -->

**1. What does the field currently believe that might be wrong?**

The field assumes that **more agent security scanners = better agent security**. Scanner developers (AgentSeal, Enkrypt AI, Sigil, MEDUSA, Microsoft AGT) implicitly claim that running their tool improves your security posture. Practitioners assume that if a scanner finds X vulnerabilities, their system has approximately X real issues. But this assumption has never been tested — no one has measured what fraction of scanner findings are real, what they miss, or whether running two scanners is better than running one. The SAST/DAST field learned this lesson the hard way: out-of-box false positive rates are 40-60% for SAST tools (Pixee/Autonoma analysis, 2025). The agent security scanning field has not yet confronted this same measurement problem, and may be worse because the underlying threat taxonomy (OWASP agentic AI risks) is less mature than traditional web app CWEs.

**The assumption that threatens my OWN emerging hypothesis:** I am assuming that scanner disagreement is a MEASUREMENT problem solvable by better calibration. But it might instead be a DEFINITIONAL problem — scanners may disagree because there is no shared ontology of what constitutes an "agent security vulnerability" vs a "design choice" vs a "configuration issue." If the category boundaries themselves are contested, statistical comparison of scanners is premature. This is a genuine risk to my approach.

**2. Lakatos test — does your question predict a novel fact or accommodate a known one?**

| Test | Answer |
|---|---|
| **If I run this study, could the result go EITHER WAY?** | Yes — scanners might show systematic specialization (each best at different threat types) OR generalized noise (most scanners no better than random on most categories). The direction is unpredictable. |
| **Would an expert in this field be SURPRISED by any possible outcome?** | Yes — if scanner agreement is near-zero on any major threat category, that would surprise scanner developers who assume their tool works. If one scanner dominates across ALL categories, that would surprise the community which assumes different tools have different strengths. A manufacturing QA specialist would be surprised if OC curves show the field is operating at "consumer risk" >50% (accepting >50% defective lots). |
| **Am I applying a KNOWN method to a NEW domain where the general result is expected?** | Partially — AQL/OC curves are known in manufacturing, but their application to agent security scanner evaluation is novel AND the results are not predictable from the method alone. The method provides the FRAMEWORK for comparison, not the ANSWER. Unlike SEIR on power-law graphs where the math predetermines the result (C7 lesson), OC curves reveal empirical properties of the scanners being tested — the curves are fitted to data, not derived from theory. |

**Research question:** Do agent security scanners (AgentSeal, Enkrypt AI, Microsoft AGT, and others) exhibit statistically distinguishable detection effectiveness when evaluated against a common ground-truth vulnerability corpus using Operating Characteristic curve methodology adapted from manufacturing quality assurance?

> Traces to OBS-1 (scanner proliferation without measurement), OBS-3 (66% vs 33% divergent findings), OBS-7 (existing benchmarks measure models not scanners).

---

## §1 Observation Link

<!-- gate:research_question_spec §1 entries:1 -->

| # | Observation ID | Source (from OBSERVATION_LOG) | Signal/Pattern Quoted |
|---|---|---|---|
| 1 | OBS-1 | Industry tooling landscape | "At least 9 distinct agent security scanners now exist... No standardized benchmark exists to compare their detection effectiveness, false positive rates, or coverage overlap." |
| 2 | OBS-3 | AgentSeal blog + Enkrypt AI | "AgentSeal scanned 1,808 MCP servers (66% had findings)... Enkrypt AI scanned 1,000 MCP servers (33% critical). These numbers are substantially different... suggesting scanner calibration and threshold definition vary enormously and lack standardization." |
| 3 | OBS-7 | arxiv (MCP-SafetyBench, MCP Security Bench) | "Two benchmark papers exist... These benchmark the MODEL's safety behavior when using MCP, NOT the scanner/tool detection effectiveness. The gap is scanner-vs-scanner comparison, not model-vs-model." |
| 4 | PAT-1 | Pattern Notes | "Scanner proliferation without measurement... analogous to having multiple medical diagnostic tests but no ROC curve comparison." |
| 5 | PAT-2 | Pattern Notes | "Measurement methodology exists but hasn't been applied to scanners... the measurement gap is at the meta-level (measuring the measurers)." |

<!-- /gate:research_question_spec §1 -->

### §1.1 Question Lineage

**Required field:** What specific limitation of the best prior work defines this question?

| Prior work (citation) | Its stated limitation or boundary | How your question addresses this limitation |
|---|---|---|
| Agent Security Bench (ASB), Zhang et al., ICLR 2025 (arxiv 2410.02644) | ASB benchmarks 27 attack/defense methods across 10 scenarios but evaluates the MODEL's vulnerability to attacks, not the SCANNER's ability to detect them. It does not measure false positive rates or detection coverage of scanning tools. | Our question evaluates the detection TOOLS, not the models being attacked. We measure scanner effectiveness using the same ground-truth approach ASB uses for model evaluation. |
| MCP-SafetyBench, ICLR 2026 (arxiv 2512.15163) | Evaluates LLM safety when interacting with real MCP servers across 20 attack types and 5 domains. Boundary: measures model behavior, not whether scanning tools would catch the vulnerabilities before deployment. | We use MCP-SafetyBench's attack taxonomy as one input to the ground-truth corpus, but evaluate scanner detection of those attack types rather than model resistance to them. |
| MCPSecBench, February 2026 (arxiv 2508.13220) | Establishes 17 attack types across 4 attack surfaces for MCP. Boundary: provides a taxonomy and test harness for attacks, does not evaluate third-party scanner detection performance against the taxonomy. | We adapt MCPSecBench's attack taxonomy categories for ground-truth labeling, then measure whether scanners actually detect what the taxonomy says should be detectable. |
| OWASP Benchmark for SAST/DAST (v1.2) | Provides 2,740 test cases for traditional web app scanners with Youden Index scoring. Boundary: covers Java web apps only; no equivalent exists for agent security tools, MCP servers, or AI-specific vulnerability classes. | We create the agent-security equivalent of the OWASP Benchmark — a scored test suite with known-vulnerable and known-safe cases against which scanner tools are measured. This is the methodological gap: the OWASP project solved this for web scanners; no one has done it for agent scanners. |

**Self-test:** The prior works' boundaries are clear and explicitly stated: they all benchmark MODEL behavior, not TOOL effectiveness. Our question targets the gap between "knowing what attacks exist" and "knowing whether your scanner detects them." The OWASP Benchmark precedent from traditional AppSec proves this question type produces high-impact, long-lived artifacts.

---

## §2 Alternatives Considered

<!-- gate:research_question_spec §2 entries:2 -->

### Alternative 1

| Field | Content |
|---|---|
| **Context** | OBS-2 (Liu et al.) demonstrated successful honeypot/canary methodology for measuring LLM supply chain attacks. Could adapt this to measure scanner effectiveness by deploying honeypot MCP servers with known vulnerabilities and seeing which scanners catch them. |
| **Alternative question** | Can honeypot MCP servers with planted vulnerabilities differentiate scanner detection rates in a live-deployment setting? |
| **Why rejected** | Requires deploying infrastructure (honeypot MCP servers) that adds operational complexity beyond a single research cycle. Also introduces confounds: scanner behavior on live vs static analysis differs. The corpus-based approach (constructing ground-truth test cases) is more controlled and reproducible in one cycle. |
| **Consequences of rejection** | We lose ecological validity — real-world scanner behavior may differ from behavior on a curated test corpus. We note this as a threat to validity and recommend live-deployment validation as follow-up work. |

### Alternative 2

| Field | Content |
|---|---|
| **Context** | OBS-5 (Microsoft AGT) covers all 10 OWASP agentic AI risks. Could focus on evaluating AGT specifically as the new dominant tool, measuring its coverage gaps. |
| **Alternative question** | Does Microsoft Agent Governance Toolkit's coverage of all 10 OWASP agentic AI risks translate to superior detection rates compared to specialized single-purpose scanners? |
| **Why rejected** | Single-tool evaluation is too narrow for a research contribution — it's a product review, not a research finding. The comparative framework (multiple scanners on common ground truth) produces a reusable methodology, not a point-in-time vendor comparison. Also: AGT focuses on runtime policy enforcement, not static vulnerability scanning, making direct comparison with scanners like AgentSeal methodologically questionable. |
| **Consequences of rejection** | We lose depth on the most impactful single tool in the space. We mitigate by including AGT as one of the scanners evaluated (where applicable to its scope), rather than making it the sole subject. |

### Alternative 3

| Field | Content |
|---|---|
| **Context** | The definitional problem identified in §0a — scanner disagreement might stem from lack of shared vulnerability ontology rather than detection quality differences. |
| **Alternative question** | Is the primary source of inter-scanner disagreement definitional (what counts as a vulnerability) or operational (how well each scanner detects agreed-upon vulnerabilities)? |
| **Why rejected** | This is actually a BETTER question but harder to answer computationally in one cycle. It requires qualitative analysis of scanner rule definitions, which are often proprietary. However, our chosen question's OC curve analysis will IMPLICITLY reveal this: if scanners agree on some threat categories but diverge wildly on others, that pattern distinguishes definitional from operational disagreement. |
| **Consequences of rejection** | We may conflate definitional and operational disagreement in our headline metrics. We mitigate by analyzing per-category scanner agreement separately, which partially decomposes the two sources of disagreement. |

<!-- /gate:research_question_spec §2 -->

### Adjacent Question Mapping

| Adjacent question not pursued | What you'd lose by pursuing it instead | Evidence your chosen question is higher-impact |
|---|---|---|
| "What is the optimal architecture for an agent security scanner?" (build-focused) | Lose measurement/evaluation focus; would produce yet another scanner (the 10th) rather than measuring the existing 9. | OBS-5 (Microsoft AGT release) demonstrates that major vendors are commoditizing scanner capability. The gap is measurement, not more scanning tools. PAT-3: "The research question shifts from 'build a scanner' to 'measure scanner effectiveness.'" |

### Boundary-Spanning Feasibility Check

| Check | Answer |
|---|---|
| **Closest methodological analog** | OWASP Benchmark Project for SAST/DAST tools (web application security domain) — uses Youden Index scoring on ground-truth test cases. |
| **Is the analog from a different domain than your research?** | Partially — OWASP Benchmark is from traditional application security, which is adjacent to but distinct from agent security. The OWASP Benchmark methodology itself is domain-specific (Java web apps). The deeper cross-domain import is AQL/OC curves from manufacturing QA, which IS from a genuinely different domain. |
| **What genuine cross-domain import could strengthen the question?** | AQL Operating Characteristic curves from manufacturing quality assurance (ISO 2859-1). This provides: (1) a formally defined framework for comparing inspection systems, (2) quantification of producer risk (FP) and consumer risk (FN) on a common scale, (3) the concept of "inspection level" that maps to scanner sensitivity settings. The OWASP Benchmark uses Youden Index, which is one-dimensional. OC curves are two-dimensional and allow threshold-independent comparison — strictly more informative. |

### Formulation-Level Predetermination Check

| Check | Answer |
|---|---|
| **What is the imported method's core mathematical relationship?** | OC curve: P(accept) = f(p, n, c) where p = actual defect rate, n = sample size, c = acceptance number. For continuous quality, this becomes the ROC analog: P(detect) = f(true_vuln_rate, scanner_sensitivity, scanner_threshold). |
| **What variable does this relationship depend on?** | True vulnerability rate (p) and scanner parameters (sensitivity, threshold). |
| **Is that variable the same as (or monotonic function of) your comparison metric?** | No — we compare SCANNERS, not vulnerability rates. The OC curve REVEALS scanner properties; it doesn't predetermine them. Each scanner produces a different OC curve shape. The comparison metric (area under OC curve, or Youden Index at operating point) is an empirical quantity, not derivable from the method's math. This is unlike SEIR on power-law graphs where beta_k = beta * k makes the result a function of degree by construction. |
| **If yes: what alternative formulation would NOT be predetermined?** | N/A — the formulation is not predetermined. The OC curves are fitted to empirical scanner performance data, not derived from theory. |

### Import Depth Verification

| Depth Check | Answer |
|---|---|
| **What conceptual FRAMEWORK from the source domain are you engaging with?** | ISO 2859-1 acceptance sampling framework. Core concepts: (1) producer risk vs consumer risk as dual optimization objectives, (2) Operating Characteristic curves as the canonical representation of inspection system performance, (3) Average Outgoing Quality Limit (AOQL) as the worst-case quality level after inspection. In agent security terms: producer risk = scanner vendor's false positive rate (wrongly flagging safe MCP servers); consumer risk = practitioner's false negative rate (passing vulnerable servers as safe). |
| **How did you ADAPT it for your target domain's constraints?** | Manufacturing QA inspects discrete lots with binary accept/reject. Agent security scanners produce multi-category findings with severity ratings. Adaptation: (1) treat each vulnerability category as a separate "defect type" with its own OC curve, (2) map scanner severity thresholds to acceptance number (c) in the sampling plan, (3) construct AOQL analog for each scanner — "what is the worst vulnerability density that passes through this scanner undetected?" |
| **What would a specialist in the SOURCE domain recognize in your work?** | A quality engineer would recognize: OC curve shapes and their interpretation (steep = discriminating, flat = unreliable), the producer-risk/consumer-risk tradeoff visualization, AOQL calculations, and the concept of "inspection level" (how thorough the scan). They would understand our comparison methodology immediately because it uses their standard framework applied to a new "product" (MCP server security). |

---

## §3 Gap Identification

<!-- gate:research_question_spec §3 entries:1 -->

| # | Gap Description | Evidence of Gap | Gap Type |
|---|---|---|---|
| 1 | No benchmark exists for comparing agent security scanner detection effectiveness. Three MCP security benchmarks exist (MCP-SafetyBench, MSB, MCPSecBench) but all measure model/agent behavior, not scanner tool performance. | Searched arxiv for "agent security scanner benchmark comparison" (0 results targeting scanner evaluation); searched OWASP for agent-specific benchmark (none exists — OWASP Benchmark covers Java web apps only); checked AgentSeal, Enkrypt AI publications (self-reported metrics only, no cross-scanner comparison). | Tried in wrong domain — the benchmarking methodology exists in traditional AppSec (OWASP Benchmark) but has not been transferred to agent security scanning. |
| 2 | No statistical framework exists for quantifying scanner calibration or comparing scanners threshold-independently. | AgentSeal reports "66% findings" and Enkrypt AI reports "33% critical" — these numbers are not comparable because severity thresholds differ. No published work applies OC curves or ROC analysis to agent security scanners. Searched "operating characteristic curve security scanner" and "AQL agent security" (0 relevant results). | Nobody tried — the cross-domain import from manufacturing QA to agent security tool evaluation has not been attempted. |
| 3 | The 30 CVEs filed against MCP servers in Jan-Feb 2026 provide ground truth, but no one has measured which scanners detect which CVEs. | CVE databases (NVD, GitHub Security Advisories) contain the CVEs; scanner vendors do not publish detection rates against known CVEs. Searched "{scanner_name} CVE detection rate" for AgentSeal, Enkrypt AI, Sigil — no results. | Nobody tried — the ground truth exists but hasn't been used for comparative evaluation. |

<!-- /gate:research_question_spec §3 -->

---

## §3b Precision Escalation

| Current best answer in the field | Its precision / resolution / scale | Source |
|---|---|---|
| AgentSeal scanned 1,808 MCP servers and reported 66% had findings. Enkrypt AI scanned 1,000 and reported 33% critical. These are the largest-scale agent security scans published. | Binary outcome per server (has finding / no finding OR critical / not critical). No per-category breakdown. No false positive quantification against known-safe baseline. No scanner-vs-scanner comparison on same corpus. | AgentSeal blog (2026); Enkrypt AI blog (2026) |

| Dimension escalated | Current level | Your target level | Why this transformation matters |
|---|---|---|---|
| Resolution | Binary (finding/no-finding per server) | Per-category detection rate with OC curves (detection probability as continuous function of true vulnerability density, per vulnerability category, per scanner) | Transforms "Scanner X found stuff" into "Scanner X has 0.85 sensitivity for prompt injection but 0.30 for data exfiltration, with FP rate of 0.12." This is the difference between a pregnancy test (yes/no) and a blood panel (quantified per analyte). |
| Scale of comparison | Self-reported single-scanner metrics | Multi-scanner comparison on identical ground truth with statistical significance testing | Transforms vendor claims into independently verifiable comparative data. The OWASP Benchmark did this for web scanners and it changed how enterprises evaluate SAST/DAST tools. |
| Calibration | No calibration data exists | OC curves with producer risk and consumer risk quantified at multiple operating points | Enables practitioners to choose scanners based on their risk tolerance (e.g., "I need low false negatives even at the cost of false positives" → Scanner A; "I need low false positives because alert fatigue is killing my team" → Scanner B). |

**Self-test:** This is a NEW question, not a scale-up. The current best cannot answer "which scanner should I use for which threat type?" at ANY scale because the comparison framework does not exist. Building the framework is the contribution.

---

## §4 Assumption Challenge

<!-- gate:research_question_spec §4 entries:1 -->

| # | Assumption the Field Holds | Sources Holding This Assumption | Contradiction Search Results | Why It Might Be Wrong |
|---|---|---|---|---|
| 1 | "Running an agent security scanner improves your security posture." | AgentSeal ("We scanned 1,808 MCP servers" — implying scanning = finding vulnerabilities = improved security); Enkrypt AI ("33% had critical vulnerabilities" — implying the scan surfaced real issues); Microsoft AGT documentation (claims "sub-millisecond policy enforcement" as a security improvement) | Searched for "agent security scanner false positive rate" — no published FP rates found for any agent-specific scanner. Searched "security scanner alert fatigue agent" — found general AppSec data: SAST tools have 40-60% FP rates out of box (Pixee/Autonoma, 2025); Contrast Security reports 98% of alerts are noise in traditional scanners. No contradiction evidence specific to agent scanners, but the traditional AppSec precedent strongly suggests unvalidated agent scanners could have similar or worse FP rates. | If agent security scanners have FP rates comparable to SAST tools (40-60%), then "running a scanner" might degrade security posture by consuming team bandwidth on false alerts while creating false confidence that the real issues were found. The scanner proliferation (9+ tools) may be making this worse, not better. |
| 2 | "MCP security benchmarks (MCP-SafetyBench, MSB, MCPSecBench) adequately characterize the agent security threat landscape." | MCP-SafetyBench (ICLR 2026) — positions itself as comprehensive with 20 attack types and 5 domains; MCPSecBench (Feb 2026) — claims "comprehensive taxonomy" with 17 attack types and 4 attack surfaces | Searched for "MCP benchmark scanner detection" and "MCP benchmark tool evaluation" — 0 results. All three benchmarks measure model behavior, not tool effectiveness. | These benchmarks characterize what attacks EXIST, not whether your TOOLS detect them. A practitioner who scores well on MCP-SafetyBench knows their model resists attacks but has no data on whether their scanner would have caught the vulnerable server configuration before deployment. The benchmarks create false confidence at the tool selection layer. |

<!-- /gate:research_question_spec §4 -->

### §4.1 Paradigm Challenge Assessment

| Unquestioned assumption | What reversal looks like | What changes in your approach if reversed |
|---|---|---|
| "Agent security scanners should be evaluated by their detection rate (what they find)." | "Agent security scanners should be evaluated by their CALIBRATION (whether what they find is real and whether what they miss matters)." | Instead of measuring how many findings each scanner reports (which is what AgentSeal's 66% and Enkrypt AI's 33% do), we measure the OC curve — the probability of correctly classifying servers at each vulnerability density level. A scanner that finds fewer things but is well-calibrated (high true positive rate, low false positive rate) is more useful than one that finds many things but can't distinguish real from false. The paradigm shift: from "detection count" to "calibration quality." |
| "Scanner comparison requires running all scanners on the same servers." | "Scanner comparison requires running all scanners against a CONTROLLED ground-truth corpus where the correct answers are known." | This reversal is the OWASP Benchmark insight applied to agent security. Instead of comparing scanner outputs on unknown real-world servers (where we don't know the ground truth), we construct a corpus with known-vulnerable and known-safe test cases and measure each scanner's accuracy. The paradigm shift: from "coverage" (how much did you scan?) to "accuracy" (how right were you?). |

**Self-test:** Reversing these assumptions fundamentally changes the experimental design — from a survey of scanner outputs to a controlled evaluation of scanner accuracy. This is not a conventional question with a paradigm label attached; the reversal drives the methodology.

### §4.2 Novelty Pre-Mortem

Self-score: **PARTIALLY PREDICTABLE**

**Predictable component:** That scanners will disagree with each other — this is expected from the AgentSeal/Enkrypt AI divergence (OBS-3) and from SAST/DAST precedent (traditional tools also disagree).

**Unpredictable components:**
1. The STRUCTURE of disagreement: Is it systematic (each scanner specialized in different categories) or random (some scanners are just noise generators)? No theory predicts this.
2. The MAGNITUDE: How far apart are scanner OC curves? In traditional AppSec, the gap between best and worst DAST tools is ~50 Youden Index points. Agent security could be tighter (tools are all rule-based) or wider (less mature field, more variation).
3. Whether any scanner achieves AOQL below practical relevance thresholds — i.e., whether any current scanner is "good enough" by manufacturing QA standards.
4. The category-level profile: Which OWASP agentic AI risk categories have the best/worst scanner coverage? This directly informs where practitioners are most exposed.

**Source of partial predictability:** General AppSec literature predicts that unvalidated security scanners have high FP rates and variable detection. We predict agent security scanners will show similar patterns, but the agent-specific threat taxonomy (prompt injection, tool poisoning, data exfiltration via MCP) may reveal novel patterns not seen in traditional web scanning.

**Alternative that shifts the unpredictable component into primary frame:**

| Alternative question | What makes it less predictable | Trade-off vs current question |
|---|---|---|
| "Does the manufacturing QA concept of Average Outgoing Quality Limit (AOQL) reveal that current agent security scanning practices leave more vulnerability through than practitioners believe, and at what threshold does adding a second scanner produce diminishing returns?" | The AOQL calculation requires empirical OC curve data that doesn't exist — the answer is entirely data-dependent and could surprise in either direction (current scanning might be better than expected, OR the AOQL might be so high that current scanning is essentially theater). The "diminishing returns of multiple scanners" component is novel — no one has studied scanner complementarity in agent security. | More focused on the practitioner decision ("should I run multiple scanners?") but harder to execute: requires enough ground-truth data to compute reliable AOQL estimates. The current question is a necessary precursor — you need OC curves before you can compute AOQL. |

**Decision:** Proceed with the current question but incorporate the AOQL and scanner complementarity analysis as a secondary research objective, contingent on sufficient ground-truth data quality. This elevates the unpredictable component without sacrificing feasibility.

---

## §5 Pipeline Signal Connection

<!-- gate:research_question_spec §5 required -->

```
Run: sqlite3 ~/singularity.db "SELECT * FROM v_question_inputs;"
```

<!-- queried: v_question_inputs, 88 rows -->

**Key signals relevant to this question:**

| Signal | Relevance |
|---|---|
| 88 hypotheses in pipeline, 7 in agent security domain | Our question extends the agent security research program with a meta-level contribution (evaluating the tools, not the attacks) |
| SH-5762: "Purpose-built scanner detects >20% more injection vectors than VirusTotal" | Directly relevant — our question would test this hypothesis empirically by comparing scanner detection across multiple tools |
| SH-5773/5774/5775: PyPI scanner, GitHub Action, MCP server adoption hypotheses | Our benchmark methodology could provide credibility evidence for these pipeline tools — if they score well on the benchmark, it validates the pipeline's tooling investments |
| SH-5776: "Auto-refreshed benchmark becomes reference link" | Our research artifact (the benchmark corpus + scoring methodology) IS the benchmark this hypothesis references |
| HSE-AUDIT-001/002/003: Agent framework vulnerability hypotheses | Ground-truth vulnerability types for our benchmark corpus can draw from these pre-registered hypotheses about serialization, supply chain, and injection vectors |
| Cycle 7 limitations #5, #7, #9 | L5 (non-diluting attacks), L7 (fixed absorption), L9 (single case study) — our multi-scanner comparison on diverse threat categories addresses all three by providing empirical data on how real detection systems handle diverse attack types across multiple tools |

<!-- /gate:research_question_spec §5 -->

### §5b Method History

```
sqlite3 ~/singularity.db "SELECT method_name, source_domain, applied_domain, bs_score 
FROM methodologies ORDER BY bs_score DESC;"
```

**Key findings from method history:**

| Method | Source Domain | Applied Domain | BS Score |
|---|---|---|---|
| Acemoglu financial contagion | mathematical economics | AI supply chain security | 7 |
| Category design | business strategy | cold-start distribution | 7 |
| Social immunity | behavioral ecology | AI agent security | 7 |
| Network controllability | network science | AI security | 6 |
| Process isolation / MAC / circuit breakers | Unix/SELinux/distributed systems | agent security | 6 |
| Broadcast contagion | information epidemiology | AI supply chain security | 6 |
| ATT&CK coverage mapping | cybersecurity | AI security (ATLAS) | 4 |

**Pattern:** Cross-domain imports (source != applied) score BS=6-7. Same-domain imports (cybersecurity → AI security) score BS=4. Manufacturing QA (AQL/OC curves) → agent security scanner evaluation would be a genuinely cross-domain import (ISO 2859-1 from manufacturing → AI security tooling), consistent with BS=6-7 based on historical data.

**Process changes from prior cycles:**

| Proposal | Target | Change |
|---|---|---|
| execution_fidelity | R | ED statistical plan must match FINDINGS — all specified analyses must be performed |
| template_gap | G | Generalizability consistently below threshold (5 vs 6 target) — need explicit boundary statements |
| question_design | N | N=5 from predictable questions — need unpredictable framing at Stage 1 |

**Implications for our design:** The N=5 warning is directly relevant — our §4.2 novelty pre-mortem addresses this by identifying unpredictable components. The G gap means we must design for explicit generalizability from the start (multiple vulnerability categories, multiple scanners, boundary statements about what doesn't generalize). The R gap means every statistical analysis we plan must be executed.

---

## §6 Question Gate Checklist

| # | Check | Status | Notes |
|---|---|---|---|
| 1 | Question statement in §0 is one sentence and traceable to observation | [x] | Traces to OBS-1, OBS-3, OBS-7 |
| 2 | ≥1 observation linked in §1 with direct quote | [x] | 5 observations linked with direct quotes |
| 3 | ≥2 alternatives documented in §2 with rejection rationale | [x] | 3 alternatives + 1 adjacent question |
| 4 | ≥1 gap cited with evidence in §3 | [x] | 3 gaps with evidence and search documentation |
| 5 | ≥2 papers cited in §4 assumption challenge | [x] | AgentSeal, Enkrypt AI, Microsoft AGT, MCP-SafetyBench, MCPSecBench cited |
| 6 | Pipeline signal connection queried in §5 (not placeholder) | [x] | v_question_inputs queried, 88 rows, key signals extracted |
| 7 | §4.2 Novelty Pre-Mortem completed — if PREDICTABLE, alternatives provided | [x] | PARTIALLY PREDICTABLE — 1 alternative provided that shifts unpredictable component to primary frame |
