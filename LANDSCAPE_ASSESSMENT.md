# LANDSCAPE ASSESSMENT

<!-- version: 0.1 -->
<!-- created: 2026-04-14 -->
<!-- stage: 2 -->
<!-- methodology_status: partial — stages 0-2 methodology from Phase B.1 -->

> **Purpose:** Force systematic landscape mapping before hypothesis formation.
> Prevent "I'll test X" without "here's what's been done and where the gap is."
> This template defines WHAT to document about the landscape, not HOW to conduct
> a systematic review. The middle loop discovers process.

## Prediction (GPL-07)

Before scanning, I predict landscape density: **emerging** (between sparse and well-studied).

Rationale:
- MCP security benchmarks exist (3 papers), but none evaluate scanner tools — the model-evaluation space is studied, the tool-evaluation space is sparse
- The traditional AppSec scanner evaluation space is well-studied (OWASP Benchmark, Miercom, Tolly), so the METHODOLOGY exists but hasn't been transferred
- The agent security scanner space itself is 6-12 months old — too young for systematic comparisons
- I predict finding 5-8 relevant works, with most either (a) benchmarking models not scanners, or (b) evaluating traditional (non-agent) scanners

---

## §0 Search Protocol

<!-- gate:landscape_assessment §0 required -->

| Field | Value |
|---|---|
| **Databases queried** | arXiv (via WebSearch), Google Scholar (via WebSearch), NVD/CVE databases, GitHub (via WebSearch for READMEs and docs), OWASP project pages, vendor blogs (AgentSeal, Enkrypt AI, Microsoft, Cisco), industry press (Help Net Security, InfoWorld, CybersecurityNews) |
| **Search terms** | "agent security scanner benchmark comparison", "MCP security scanner evaluation", "OWASP Benchmark SAST DAST Youden Index", "MCP-SafetyBench", "MCPSecBench", "MCP-DPT defense placement taxonomy", "operating characteristic curve acceptance quality level ISO 2859", "ROC curve diagnostic test comparison meta-analysis", "SAST scanner false positive rate comparison empirical", "Miercom DAST scanner benchmark 2026", "Cisco MCP scanner", "MEDUSA agent security scanner", "Sigil supply chain scanner", "Ant Group MCPScan" |
| **Date range** | 2024-01-01 to 2026-04-14 (primary); pre-2024 for foundational methodology (OWASP Benchmark, ISO 2859, ROC meta-analysis) |
| **Inclusion criteria** | (1) Papers/tools that benchmark or evaluate security detection tools (not just vulnerability taxonomies), (2) MCP security benchmarks (even if model-focused — to map what exists), (3) Cross-domain evaluation methodologies (OC curves, ROC meta-analysis, SAST/DAST benchmarking), (4) Active agent security scanners with published methodology or results |
| **Exclusion criteria** | (1) Generic vulnerability scanner product reviews without methodology, (2) MCP protocol specifications without security evaluation, (3) LLM safety benchmarks without tool/scanner component, (4) Papers behind paywalls without accessible preprint |
| **Total results screened** | ~85 across all search queries (many duplicates across queries) |
| **Results included** | 14 works inventoried (§1), plus 4 adjacent-field methodologies (§1b) |

<!-- /gate:landscape_assessment §0 -->

---

## §1 Prior Work Inventory

<!-- gate:landscape_assessment §1 entries:5 -->

| # | Reference | What It Does | Methodology | Key Results | Limitations | Relevance to Our Question |
|---|---|---|---|---|---|---|
| 1 | OWASP Benchmark Project v1.2 (owasp.org/www-project-benchmark) | Evaluates SAST/DAST/IAST tools against a ground-truth test suite of 2,740 Java web app test cases with known-vulnerable and known-safe classifications | Youden Index scoring: TPR - FPR for each tool. Binary classification per test case (TP/FP/TN/FN). Scorecard visualization. Fully runnable web app so DAST tools can test dynamically. | Commercial tools range from Youden ~0.1 to ~0.7. Many tools cluster near random (0.0). False positive rates vary 10-80% across tools. Established as THE reference for SAST/DAST comparison since 2015. | Java-only (no Python, TypeScript). Web app vulnerabilities only (CWEs, not agent-specific threats). No coverage of AI/agent attack surfaces. No OC curve or threshold-independent analysis — Youden is a single-point metric. Test cases are static, not updated for modern attack patterns. | **Direct methodological precedent.** Our work is the agent-security equivalent of OWASP Benchmark. Their Youden Index approach is our starting point, which we extend with OC curves for threshold-independent comparison. |
| 2 | MCP-SafetyBench (Xie et al., ICLR 2026, arxiv 2512.15163) | Benchmarks LLM safety when using real MCP servers across 5 domains (browser, finance, navigation, repo management, web search) | 20 attack types spanning server/host/user sides. Multi-turn evaluation requiring multi-step reasoning and cross-server coordination. Measures Defense Success Rate vs Task Success Rate tradeoff. | All models remain vulnerable. Clear negative correlation between defense success and task success. Host-side attacks achieve highest success rates. Larger models not consistently safer. | **Evaluates MODEL behavior, not SCANNER detection.** Does not measure whether any scanning tool would detect the vulnerabilities before deployment. No scanner comparison. No false positive analysis. | **Taxonomy source, not methodology precedent.** Their 20 attack types inform our ground-truth corpus categories, but their evaluation target (model safety) is orthogonal to ours (scanner detection effectiveness). |
| 3 | MCPSecBench (AIS2Lab, arxiv 2508.13220) | Systematic security benchmark and playground for testing MCP across 3 major platforms (Claude, OpenAI, Cursor) | 17 attack types across 4 attack surfaces (client, protocol, server, host). Modular test harness with attack scripts, MCP servers/clients, and protection mechanisms. Open-source at github.com/AIS2Lab/MCPSecBench. | All attack surfaces yield successful compromises. Core vulnerabilities universal across platforms. Protection mechanisms <30% average success rate. Server-side and client-side attacks show high variability across hosts. | **Same gap as MCP-SafetyBench:** evaluates platform vulnerability to attacks, not scanner detection of vulnerabilities. No third-party scanner evaluation. No detection rate measurement. | **Attack taxonomy + test harness source.** Their modular platform could potentially be adapted as infrastructure for scanner testing (run scanners against their test servers), but this adaptation has not been done. |
| 4 | MCP Security Bench / MSB (arxiv 2510.15994) | Benchmarks attacks against MCP in LLM agents | Attack taxonomy and evaluation harness for MCP-specific attacks against LLM agents | Documents attack success rates against MCP-enabled agents | Same model-focused limitation: measures whether attacks succeed against agents, not whether scanners detect vulnerable configurations | **Third confirmation of the gap:** three independent MCP benchmarks all evaluate model/agent behavior, none evaluate scanner tools. The gap is systematic, not accidental. |
| 5 | AgentSeal scan results (agentseal.org/blog, 2026) | Scanned 1,808 MCP servers using 4-layer pipeline (pattern detection, deobfuscation, semantic analysis, optional LLM judge) + red-teaming with 380+ attack probes | Multi-layer analysis pipeline. 9 analyzers for MCP security scoring. Internal validation against 120 known-benign servers for FP estimation. Public security registry at agentseal.org/mcp. | 66% of servers had security findings. ~4.2% false positive rate on known-benign set. Security scores published for 800+ servers. | Self-reported metrics only — no independent validation. FP rate measured on known-benign set only (not against known-vulnerable ground truth). No comparison with other scanners on same corpus. No per-category breakdown of detection rates. | **Primary scanner data source.** Largest published MCP scan dataset. Their 4.2% FP rate claim is testable against our ground-truth corpus. Their scoring methodology is the closest existing thing to what we propose, but single-scanner only. |
| 6 | Enkrypt AI MCP scan results (enkryptai.com/blog, 2026) | Scanned 1,000+ MCP servers with static analysis focus on supply chain security | Static code analysis for command injection, insecure configurations, exposed secrets. Severity classification (critical/high/medium/low). | 33% had critical vulnerabilities. Servers averaged 5.2 vulnerabilities each. | Self-reported metrics. Different severity threshold than AgentSeal (33% "critical" vs 66% "had findings"). No FP rate published. No methodology transparency for classification rules. | **Key comparand.** The 33% vs 66% divergence with AgentSeal on overlapping server populations demonstrates the calibration problem our research addresses. Different thresholds, different methodologies, incomparable numbers. |
| 7 | Miercom DAST Scanner Benchmark 2026 (miercom.com) | Independent third-party evaluation of DAST scanners (Invicti, competitors) against ground-truth vulnerable applications | 11 intentionally vulnerable apps (APIs, SPAs, GraphQL, traditional web). Ground truth = canonical vulnerability list. Independent scan execution. Miercom also built their own vulnerable apps for cross-validation. Metrics: detection accuracy by severity, scan speed, behavioral consistency. | Invicti detected all 31 critical vulnerabilities. Other tools missed 5-15 critical vulns. Consistent accuracy more important than raw scan speed. | Traditional web app focus — no AI/agent vulnerabilities. Vendor-commissioned (Invicti supplied test apps, though Miercom validated independently). No OC curve or threshold-independent analysis. | **Closest methodological analog in traditional security.** Their approach (known-vulnerable apps + independent evaluation + detection accuracy measurement) is exactly what we propose for agent security, minus the OC curve framework. |
| 8 | MCP-DPT: Defense-Placement Taxonomy (Rostamzadeh et al., arxiv 2604.07551, April 2026) | Maps MCP security defenses across 6 architectural layers with coverage analysis | Layer-aligned taxonomy organizing attacks by enforcement component. Maps existing academic and industry defenses onto framework. Identifies primary and secondary defense points. | Protection is uneven and predominantly tool-centric. Persistent gaps at host orchestration, transport, and supply-chain layers. Architectural misalignment > implementation flaws. | Taxonomy/mapping only — does not measure detection effectiveness of any specific tool. Qualitative coverage analysis, not quantitative measurement. | **Structural context.** Their finding that "protection is tool-centric with gaps at other layers" contextualizes why scanner comparison matters — if protection is tool-centric, the quality of those tools is critical. |
| 9 | MEDUSA (Pantheon Security, github.com/Pantheon-Security/medusa, 2026) | AI-first security scanner with 76+ analyzers, 9,600+ detection rules, repo poisoning detection for AI/ML, LLM agents, MCP servers | 79 specialized scanners. Covers AI editor CVEs (37+), traditional code vulns, AI/ML-specific issues. Breadth-focused scanning. | Claims coverage of 200 critical vulnerabilities. Includes AI editor CVEs not covered by other scanners. | No published FP rate. No independent validation. Rule count ≠ detection quality. No comparison with other scanners. | **Additional scanner for comparison.** Highest rule count among scanners surveyed. Testing whether rule count correlates with detection effectiveness would be informative. |
| 10 | Cisco MCP Scanner + DefenseClaw (cisco-ai-defense/mcp-scanner, 2026) | MCP server scanning using three engines: YARA rules, LLM-as-judge, Cisco AI Defense inspect API. DefenseClaw (RSAC 2026) adds lifecycle management. | Three-engine approach: signature-based (YARA), semantic (LLM-as-judge), behavioral code analysis (interprocedural dataflow). Detects hidden operations contradicting stated purpose. | Behavioral code scanning catches undocumented network calls, secret bcc's, system commands. Supports customizable YARA rules. | No published scan-at-scale results comparable to AgentSeal/Enkrypt. No FP/FN rates published. Enterprise-focused (Cisco AI Defense API may require license). | **Methodologically interesting comparand.** Three-engine approach (signature + LLM + behavioral) is architecturally distinct from AgentSeal (4-layer) and Enkrypt (static analysis). Tests whether architectural diversity correlates with detection profile differences. |
| 11 | Sigil (sigilsec.ai, 2026) | Supply chain threat scanner for npm, PyPI, MCP server packages | Six-phase static analysis with quarantine. Free CLI + MCP server for AI agents + CI/CD integration. | Detected 314 malicious AI skills in Feb 2026 using advanced evasion techniques (prompt injection, password-protected archives, social engineering). | Supply-chain focus — may not detect runtime vulnerabilities. No published detection rates against ground truth. | **Niche scanner for comparison.** Supply-chain specialization may show high detection in that category but low/zero in others (prompt injection at runtime, data exfiltration). |
| 12 | Ant Group MCPScan (github.com/antgroup/MCPScan, 2025-2026) | Multi-stage MCP server auditing: Stage 1 (Semgrep taint), Stage 2 (LLM description monitoring), Stage 3 (cross-file flow + LLM risk verdict) | Three-stage pipeline: static taint analysis → metadata assessment → cross-file flow reconstruction. Each stage independently toggleable. | Combines static analysis (Semgrep) with LLM judgment. Supports local and remote (GitHub) scanning. | No published FP/FN rates. No large-scale scan results. Relatively new tool with limited community adoption. | **Stage-configurable scanner.** Ability to toggle stages enables ablation-like analysis: does adding LLM judge improve detection beyond static analysis alone? |
| 13 | Snyk agent-scan (github.com/snyk/agent-scan, 2026) | Security scanner for AI agents, MCP servers, and agent skills | Enterprise-backed scanning from established security vendor (Snyk). Covers agents, MCP servers, and skills. | Limited public documentation on methodology or results. | Closed methodology. No published scan results or FP/FN data. | **Enterprise baseline.** Snyk's brand provides credibility anchor — if their scanner performs similarly to open-source alternatives, it questions the premium. |
| 14 | SAST FP Rate Studies (Autonoma/Pixee 2025, Ghost Security 2025, academic 2024) | Empirical measurement of SAST tool false positive rates across real codebases | Ghost Security: tested across ~3,000 repos. Academic (2024): 815 real vulnerable C/C++ commits. Autonoma: benchmark applications. | 91% of flagged vulns were FP (Ghost). 76% of alerts irrelevant to actual vuln (academic). 40-60% FP untuned, 10-20% tuned (Autonoma). Semgrep: 35.7% precision. Tools miss 47-80% of vulns. | Traditional code vulnerabilities, not agent/MCP-specific. But establishes baseline expectations for what "unvalidated scanner" FP rates look like. | **Calibration anchor.** If traditional SAST tools have 40-91% FP rates, agent security scanners (less mature, less tested) likely have comparable or worse rates. This is the assumption our research tests. |

<!-- /gate:landscape_assessment §1 -->

### §1.1 Benchmark as Landscape

| Question | Answer |
|---|---|
| Does a standardized competition, benchmark, or shared evaluation exist for this problem? | **No — and this absence is the core finding of the landscape assessment.** Three MCP security benchmarks exist (MCP-SafetyBench, MSB, MCPSecBench) but all evaluate model/agent behavior against attacks, not scanner detection effectiveness. The OWASP Benchmark evaluates traditional SAST/DAST tools but covers Java web apps only. The Miercom DAST Benchmark evaluates traditional DAST tools against web apps. No benchmark exists that evaluates agent security scanners against a ground-truth MCP vulnerability corpus. |
| If no: why not? What does the absence tell you about the field's maturity or the question's novelty? | The absence reflects two factors: (1) **Recency** — agent security scanners are 6-12 months old; the field hasn't had time to develop evaluation infrastructure. (2) **Misaligned benchmarking instinct** — the MCP security community benchmarks the thing being attacked (the model/agent) rather than the thing doing the detecting (the scanner). This mirrors early medical diagnostics where diseases were studied before diagnostic test accuracy was systematically evaluated. The OWASP Benchmark took ~5 years after the first SAST tools to emerge. We are at the equivalent of year 0-1 for agent security scanners. Creating this benchmark IS a substantial portion of the contribution, analogous to Milkman's megastudy where creating comparable evidence across interventions was the innovation. |

---

## §1b Adjacent Field Survey

| # | Adjacent field | Analogous problem they face | Method they use | Have they solved something you haven't? | Could you import their method? |
|---|---|---|---|---|---|
| 1 | **Manufacturing Quality Assurance (ISO 2859-1)** | Comparing inspection systems that accept/reject manufactured lots — each inspector (scanner) has different sensitivity and different thresholds, and you need to know which inspector catches defective products vs rejects good ones | **Operating Characteristic (OC) curves**: plot P(acceptance) vs true defect rate for each inspection plan. Key concepts: Producer Risk alpha (rejecting good lots = false positives), Consumer Risk beta (accepting bad lots = false negatives), Acceptable Quality Level (AQL), Reject Quality Level (RQL), Average Outgoing Quality Limit (AOQL — worst-case quality after inspection). ISO 2859-1 provides standardized sampling plans with pre-computed OC curves. Curve SHAPE reveals discriminating power: steep = discriminating inspector, flat = unreliable. | **Yes — they solved threshold-independent comparison.** OC curves compare inspectors ACROSS ALL thresholds simultaneously, unlike Youden Index which is a single operating-point metric. They also solved the "how many inspectors do I need?" question via AOQL — the worst-case defect rate that gets through even after inspection. AOQL of multiple inspectors in series can be computed to determine diminishing returns. | **Yes — this is the primary import.** Adaptation: (1) each vulnerability category = a "defect type" with its own OC curve per scanner, (2) scanner severity thresholds map to acceptance number c, (3) AOQL per scanner = worst vulnerability density passing undetected. A quality engineer would recognize our comparison framework immediately. The import is feasible because the mathematical framework (binomial/Poisson OC curve computation) is well-established and the mapping from "lot inspection" to "server scanning" is structurally clean: lot = MCP server, defect = vulnerability, inspector = scanner, accept = "pass" scan, reject = "flagged." |
| 2 | **Medical Diagnostic Test Evaluation (Cochrane Handbook Ch. 10)** | Comparing diagnostic tests (blood tests, imaging, rapid assays) that detect disease — each test has different sensitivity/specificity, and meta-analysis requires methods that handle the sensitivity-specificity tradeoff across studies using different thresholds | **Hierarchical Summary ROC (HSROC) model and bivariate meta-analysis**: accounts for threshold effects causing negative correlation between sensitivity and specificity across studies. Summary ROC curves enable threshold-independent comparison of diagnostic tests. Cochrane DTA methodology provides the gold standard for systematic reviews of diagnostic accuracy. | **Yes — they solved multi-study meta-analysis of detection accuracy.** Their bivariate model handles the exact problem we face: different scanners use different thresholds, making raw sensitivity/specificity incomparable. The HSROC approach provides a principled way to summarize scanner accuracy across operating points. They also developed QUADAS-2 (Quality Assessment of Diagnostic Accuracy Studies) — a checklist for evaluating study quality that could be adapted for scanner evaluation study quality. | **Yes — secondary import for validation.** The HSROC model is more sophisticated than OC curves for the case where we have LIMITED data points per scanner (few threshold settings). For external validation in Dispatch 2: design a "QUADAS-2 for scanner evaluation" checklist. If we frame our scanner comparison as a diagnostic accuracy study, we can leverage 20+ years of Cochrane methodology for handling heterogeneity, bias, and threshold effects. |
| 3 | **Traditional SAST/DAST Evaluation (OWASP Benchmark + Miercom)** | Comparing application security scanners against ground-truth vulnerable applications — this is the same problem but for a different vulnerability domain (web CWEs vs agent/MCP threats) | **Ground-truth test suites with Youden Index scoring** (OWASP Benchmark: 2,740 test cases, binary TP/FP/TN/FN classification) and **vendor-independent evaluation against intentionally vulnerable apps** (Miercom: 11 apps, detection accuracy by severity, independent validation with self-built vulnerable apps). | **Partially.** OWASP Benchmark solved ground-truth construction and Youden scoring for web apps. Miercom solved independent evaluation methodology. Neither provides threshold-independent comparison (both are single-operating-point). Neither covers agent/MCP vulnerability types. | **Yes — for ground-truth corpus design.** Import OWASP Benchmark's test case construction methodology (known-vulnerable + known-safe, mapped to taxonomy categories, fully reproducible). Import Miercom's independence protocol (evaluator builds own test apps to validate vendor-supplied ones). Our contribution EXTENDS these with OC curves for threshold-independent comparison — going beyond what traditional AppSec evaluation offers. |
| 4 | **Software Testing / Mutation Analysis** | Evaluating test suite quality by measuring ability to detect known faults (mutants) — analogous to evaluating scanner quality by measuring ability to detect known vulnerabilities | **Mutation scoring**: inject known faults (mutants) into code, run test suite, measure kill rate. Mutation adequacy = killed mutants / total mutants. Equivalent mutants (undetectable by definition) are identified and excluded. | **Yes — they solved the "ground truth construction" problem at scale.** Mutation operators systematically generate known-faulty variants. Applied to MCP servers: vulnerability mutation operators could generate known-vulnerable server variants from known-safe servers, creating ground truth at scale without manual curation. | **Possible secondary import for corpus scaling.** If 30 CVEs proves insufficient for statistical power, mutation-based ground truth generation could expand the corpus. Risk: mutant vulnerabilities may not reflect real-world vulnerability distributions. This is a feasibility question for Dispatch 2. |

---

## §2 Gap Map

<!-- gate:landscape_assessment §2 entries:1 -->

| # | Gap Description | Gap Type | Evidence | Opportunity Size |
|---|---|---|---|---|
| 1 | **No benchmark exists for comparing agent security scanner detection effectiveness.** Three MCP benchmarks (MCP-SafetyBench, MSB, MCPSecBench) evaluate model behavior; OWASP Benchmark evaluates traditional web scanners; Miercom evaluates traditional DAST tools. None evaluate agent security scanners (AgentSeal, Enkrypt AI, Cisco, MEDUSA, Sigil, etc.) against common ground truth. | **Tried in wrong domain** — the benchmarking methodology exists in traditional AppSec (OWASP Benchmark, Miercom) but has not been transferred to agent security scanner evaluation. The MCP security community benchmarked the wrong thing (models, not scanners). | (1) Searched "agent security scanner benchmark comparison" on arXiv — 0 results targeting scanner evaluation. (2) OWASP Benchmark covers Java web apps only. (3) Miercom DAST Benchmark covers traditional web scanners only. (4) MCP-SafetyBench, MSB, MCPSecBench all explicitly target model/agent behavior. (5) AgentSeal and Enkrypt AI publish self-reported metrics only, no cross-scanner comparison. | **HIGH.** 9+ scanners exist with no comparative evaluation. Practitioners choosing scanners have zero independent data. The OWASP Benchmark became THE reference for SAST/DAST selection — an agent security equivalent would fill an identical function for a growing market. |
| 2 | **No threshold-independent scanner comparison framework exists for any security domain.** OWASP Benchmark uses Youden Index (single operating point). Miercom measures detection at a single severity threshold. No security scanner evaluation uses OC curves, ROC analysis, or any threshold-independent comparison method. | **Nobody tried** — the manufacturing QA community uses OC curves routinely for inspection system comparison, but no security researcher has imported this framework for scanner evaluation. The medical diagnostics community uses HSROC for diagnostic test comparison, but this hasn't been applied to security tool evaluation either. | (1) Searched "operating characteristic curve security scanner" — 0 relevant results. (2) Searched "ROC curve SAST DAST comparison" — 0 results applying ROC to scanner tool comparison (ROC is used for ML model evaluation, not tool evaluation). (3) Searched "AQL agent security" — 0 results. (4) OWASP Benchmark documentation explicitly uses Youden Index, with no mention of OC curves or threshold-independent analysis. | **MEDIUM-HIGH.** The methodological contribution (OC curves for scanner evaluation) is reusable beyond agent security — it could be applied to traditional SAST/DAST evaluation too. But the opportunity depends on whether scanners actually have configurable thresholds that produce meaningfully different OC curves. |
| 3 | **Scanner output is incomparable across tools.** AgentSeal reports "66% had findings" (any severity). Enkrypt AI reports "33% had critical vulnerabilities" (critical only). These are not comparable because: (a) different severity thresholds, (b) different vulnerability taxonomies, (c) different server populations (1,808 vs 1,000), (d) different scanning methodologies (multi-layer pipeline vs static analysis). No common ground truth or shared metric exists. | **Nobody tried** — no one has run multiple scanners on the same server corpus and compared outputs. Each vendor operates in isolation. | (1) AgentSeal and Enkrypt AI blogs report results on different server populations with different severity definitions. (2) No paper or blog post compares any two agent security scanners on the same servers. (3) MCP-DPT (2604.07551) maps defenses qualitatively but does not measure detection quantitatively. | **HIGH.** This is the Milkman analogy: making evidence comparable IS the contribution. Running 3+ scanners on the same corpus with the same ground truth would be the first comparable evidence in this space. |
| 4 | **Ground-truth vulnerability corpus for MCP does not exist in benchmark-ready form.** 30 CVEs were filed Jan-Feb 2026, but these exist as NVD entries and exploit descriptions, not as reproducible test cases with known-vulnerable and known-safe server configurations. | **Nobody tried** — CVEs exist but haven't been curated into a test suite. MCP-SafetyBench has test scenarios but for model evaluation, not scanner evaluation. MCPSecBench has attack scripts but for platform testing, not scanner benchmarking. | (1) NVD contains CVE entries but not reproducible test environments. (2) No "agent security OWASP Benchmark" project exists on GitHub (searched). (3) MCPSecBench's test harness is the closest infrastructure but would need adaptation. | **MEDIUM.** Corpus construction is a prerequisite, not the research contribution itself. But the curation effort (mapping CVEs to reproducible test cases, adding known-safe controls, categorizing by threat taxonomy) is significant engineering work. |

<!-- /gate:landscape_assessment §2 -->

---

## §2b Fragmentation Diagnosis

| Question | Answer |
|---|---|
| Does evidence for your question exist in incomparable forms across studies? | **Yes — severely fragmented.** AgentSeal reports on 1,808 servers at multiple severity levels. Enkrypt AI reports on 1,000 servers at "critical" only. MEDUSA claims 9,600+ rules but no scan results. Cisco claims behavioral analysis but no scale data. Sigil detected 314 malicious skills but in supply-chain context only. Each scanner reports in its own metrics, against its own server population, using its own severity definitions. Cross-scanner comparison is currently impossible. |
| If yes: what makes them incomparable? | (1) **Different populations**: each scanner scanned different servers. (2) **Different metrics**: "findings" vs "critical vulnerabilities" vs "detection rules" vs "malicious skills." (3) **Different methodologies**: multi-layer pipeline (AgentSeal) vs static analysis (Enkrypt) vs YARA+LLM+behavioral (Cisco) vs Semgrep+LLM (Ant Group MCPScan). (4) **Different taxonomies**: no shared vocabulary for what constitutes a "vulnerability" vs "configuration issue" vs "design choice." (5) **No ground truth**: without known-correct answers, accuracy cannot be computed for any scanner. |
| If yes: what would make them comparable? | Running all scanners against a **common ground-truth corpus** with (a) known-vulnerable servers mapped to a shared taxonomy (OWASP Agentic Top 10 or MCPSecBench's 17-type taxonomy), (b) known-safe control servers, and (c) standardized output mapping that translates each scanner's findings into TP/FP/TN/FN classifications. Then applying OC curves for threshold-independent comparison. |
| Is making evidence comparable the real contribution? | **Yes — this IS a Milkman-type contribution.** The existing scanner data is like Milkman's behavioral intervention literature: many studies, different populations, different measures, no way to compare. Our ground-truth corpus + OC curve framework creates comparable evidence, just as Milkman's megastudy created comparable evidence for 54 interventions tested simultaneously. The scanner comparison results (which scanner is best for which category) are valuable but secondary to the METHODOLOGY of making comparison possible. |

---

## §3 Baseline Knowledge State

| Category | What We Know |
|---|---|
| **Known with confidence** | (1) 9+ agent security scanners exist targeting MCP/agent attack surfaces (AgentSeal, Enkrypt AI, Microsoft AGT, Cisco MCP Scanner, MEDUSA, Sigil, Snyk agent-scan, Ant Group MCPScan, mcpscan.ai). (2) Three MCP security benchmarks exist but evaluate model behavior, not scanner detection (MCP-SafetyBench, MSB, MCPSecBench). (3) 30+ CVEs were filed against MCP servers in Jan-Feb 2026. (4) Traditional SAST tools have 40-91% FP rates when untuned. (5) OWASP Benchmark methodology (Youden Index on ground-truth test cases) is the established approach for traditional scanner evaluation. (6) MCP ecosystem grew to 16,000+ servers, creating substantial attack surface. (7) Scanner architectures differ fundamentally: multi-layer pipeline (AgentSeal), static analysis (Enkrypt), YARA+LLM+behavioral (Cisco), taint+LLM multi-stage (MCPScan). |
| **Uncertain** | (1) Whether agent security scanner FP rates are comparable to traditional SAST (40-91%) or better/worse. (2) Whether scanner disagreement is primarily definitional (different vulnerability ontologies) or operational (different detection quality). (3) Whether 30 CVEs provide sufficient statistical power for OC curve computation per category. (4) Whether scanners have configurable thresholds that produce meaningfully different operating points for OC curves (some may be binary: finding/no-finding). (5) Whether scanner output formats can be reliably mapped to common TP/FP/TN/FN classifications. |
| **Contested** | (1) **What counts as a "vulnerability" vs "configuration issue":** AgentSeal flags tool description anomalies; Enkrypt focuses on code-level injection vectors; these may represent genuinely different definitions of "security finding" rather than different detection quality. (2) **Whether runtime governance (Microsoft AGT) and static scanning (AgentSeal/Enkrypt) address the same threat surface:** AGT does policy enforcement, scanners do pre-deployment detection — comparing them may be category error. (3) **Whether LLM-as-judge scanning (used by Cisco, Ant Group, AgentSeal) is reproducible:** LLM outputs are stochastic, potentially making scanner results non-deterministic and complicating ground-truth evaluation. |

---

## §4 Frontier Moat Test

<!-- gate:landscape_assessment §4 required -->

| Question | Answer |
|---|---|
| **Novelty check:** <5 similar projects on GitHub/arXiv? | **Yes, <5.** Searched GitHub for "agent security scanner benchmark" (0 results targeting scanner-vs-scanner comparison), "MCP scanner evaluation" (0 benchmark projects), "OC curve security scanner" (0 results). Searched arXiv for "agent security scanner comparison" (0 results), "operating characteristic curve vulnerability scanner" (0 results). The closest existing project is OWASP Benchmark (different domain — web apps) and Miercom DAST Benchmark (vendor-commissioned, traditional web). No project applies OC curves to any security scanner evaluation. Novelty confirmed: 0 similar projects found. |
| **Timing check:** What changed in the last 6 months enabling this? | (1) **Scanner proliferation:** From ~2 agent security scanners (mid-2025) to 9+ (April 2026). Cannot compare tools that don't exist yet. (2) **CVE ground truth:** 30 MCP CVEs in Jan-Feb 2026, including CVSS 9.6 RCE. Before this, no MCP-specific CVE corpus existed. (3) **MCP ecosystem scale:** 2,000 to 16,000+ servers. Enough servers for statistically meaningful scanning. (4) **Benchmark infrastructure:** MCPSecBench open-sourced (Feb 2026), providing modular test harness adaptable for scanner evaluation. (5) **Major vendor entry:** Microsoft AGT (April 2, 2026) and Cisco DefenseClaw (March 23, 2026) create urgency for independent comparison — practitioners must choose between vendor-backed and independent tools with no comparative data. |
| **Moat check:** What stops a funded competitor replicating in 1 month? | (1) **Ground-truth corpus construction:** Curating 30+ CVEs into reproducible test cases with known-safe controls requires security domain expertise AND MCP infrastructure knowledge. Not trivial engineering. (2) **Scanner access and execution:** Running 5+ scanners with different architectures, APIs, and configurations on the same corpus requires integration work with each tool. Some scanners may require specific environments or licenses. (3) **OC curve methodology adaptation:** Mapping manufacturing QA's OC curve framework to security scanner evaluation requires understanding both domains. The mathematical framework exists but the domain mapping is novel. (4) **Honest answer: moat is THIN.** A well-funded team (e.g., OWASP working group, NIST) could replicate within 2-3 months given the right expertise combination. The moat is timing (first to do it) and methodology (OC curves vs Youden-only), not barrier to entry. This is acceptable because the OWASP Benchmark's moat was also timing + being first, and it became the reference standard. |

<!-- /gate:landscape_assessment §4 -->

---

## §5 Cross-Engine Research Context

<!-- gate:landscape_assessment §5 required -->

```
Run: sqlite3 ~/singularity.db "SELECT * FROM v_landscape_inputs;"
```

<!-- queried: v_landscape_inputs, 2794 rows -->

**Relevant prior cycles:**

| Type | ID | Domain | Score | Status |
|---|---|---|---|---|
| prior_cycle | 1 | tool-permission-boundaries | 7.3 | completed |
| prior_cycle | 7 | AI supply chain contagion (Acemoglu shock model) | 7.7 | completed |
| prior_cycle | 8 | Social immunity | — | completed |

**Key claims from prior cycles relevant to this research:**

| Claim ID | Relevance |
|---|---|
| 83-112 | Cycle 1 empirical attack data: 5 attack classes tested against LangChain ReAct agents. 100% success for reasoning chain hijacking, 80% prompt injection, 75% tool boundary violation. These provide GROUND TRUTH for what attacks succeed — our scanners should detect the configurations that enable these attacks. |
| 85 | "Five of seven systematized AI agent attack classes are not covered by OWASP LLM Top 10 or MITRE ATLAS" — if frameworks miss these, scanners built on those frameworks likely miss them too. |
| 94 | "Reasoning chain hijacking uses normal-sounding instructions, making it undetectable by regex or keyword-based input filtering" — pattern-based scanners (YARA rules) likely cannot detect this class. This predicts scanner blind spots. |
| 108 | "Existing security frameworks focus on LLM layer, not agent-specific attack surfaces" — aligns with our observation that benchmarks evaluate models not scanners. |
| 113 | "Claude 3 Haiku achieves 92% precision@10 on vulnerability triage against CISA KEV ground truth" — demonstrates that LLM-based approaches CAN achieve high precision on security triage, relevant to LLM-as-judge scanner architectures. |

**Published content from pipeline:** 7 prior cycles completed, with Cycle 1 (tool-permission-boundaries) and Cycle 7 (supply chain contagion) directly relevant to agent security domain knowledge.

<!-- /gate:landscape_assessment §5 -->

---

## §6 EDA Readiness

| Field | Value |
|---|---|
| **Research type** | Computational |
| **Available data sources** | (1) **MCP CVE corpus:** 30+ CVEs from NVD (Jan-Feb 2026) with CVSS scores, affected components, descriptions. Accessible via NVD API. (2) **Scanner tools (open-source):** AgentSeal (pip install agentseal), Cisco MCP Scanner (pip install mcpscanner), MEDUSA (pip install medusa-scan), Ant Group MCPScan (GitHub), Sigil (npm install sigilsec), mcpscan.ai (web API). (3) **Scanner tools (limited access):** Enkrypt AI (may require account), Snyk agent-scan (may require Snyk account), Microsoft AGT (open-source but runtime governance, not static scanning). (4) **MCPSecBench test harness:** open-source at github.com/AIS2Lab/MCPSecBench — modular MCP server/client test infrastructure. (5) **AgentSeal MCP Security Registry:** 800+ scored servers at agentseal.org/mcp. |
| **EDA needed before hypothesis formation?** | Yes |
| **EDA scope** | (1) **CVE corpus feasibility:** Download 30+ MCP CVEs, classify by OWASP Agentic Top 10 category, assess whether they can be reproduced as test cases. (2) **Scanner output format survey:** Install 3-4 open-source scanners, run against 5 known-vulnerable + 5 known-safe MCP servers, document output formats and whether TP/FP/TN/FN classification is feasible. (3) **Threshold configurability check:** Determine whether each scanner has adjustable thresholds (severity cutoffs, rule sets) that would produce different operating points for OC curves. If scanners are binary (one threshold only), OC curve methodology needs modification. (4) **Statistical power estimation:** With N=30 CVEs across K categories, estimate whether per-category OC curves are feasible or if categories must be aggregated. |
| **Link to DATA_CONTRACT §6** | N/A — will be created during Dispatch 2 |

### Data Source Sample Verification

| Data source | Assumed structure | Actual (from sample) | Match? |
|---|---|---|---|
| NVD MCP CVEs | CVE ID, CVSS score, affected component, description, CWE mapping, exploit availability | Cannot verify until EDA — NVD API access required. Assumed ~30 CVEs; some may be MCP-adjacent rather than directly MCP-server vulnerabilities. Key risk: CVEs may describe the vulnerability but not provide reproducible test cases. | **UNKNOWN — requires EDA.** This is the highest-risk data assumption. If CVEs lack sufficient technical detail for test case construction, ground truth corpus will need supplementation from MCPSecBench attack scripts or manual creation. |
| AgentSeal scanner output | JSON/structured findings per server: vulnerability type, severity, description, affected tool/endpoint | Cannot verify until scanner installation. AgentSeal docs suggest structured JSON output with severity levels. | **UNKNOWN — requires EDA.** Need to verify output format maps to TP/FP/TN/FN classification. |
| Cisco MCP Scanner output | Structured findings with YARA match details, LLM judge verdict, severity | Cannot verify until scanner installation. Documentation suggests findings include rule ID, severity, and description. | **UNKNOWN — requires EDA.** Three-engine output may be more complex to map than assumed. |

**Critical uncertainty flagged:** All three data source assumptions are UNKNOWN pending EDA. The experimental design in Dispatch 2 must include an EDA phase (Phase 1) that validates these assumptions before committing to the full OC curve analysis. If scanner outputs cannot be reliably mapped to TP/FP/TN/FN, the methodology must be adapted (e.g., to agreement analysis rather than accuracy analysis).

---

## §6b Handoff to Hypothesis

**Prior work frontier** (3 strongest works and their specific limitations):

| # | Prior work | Its specific limitation that your work addresses |
|---|---|---|
| 1 | **OWASP Benchmark v1.2** — the gold standard for traditional scanner evaluation (2,740 test cases, Youden Index scoring, 10+ years of use) | Covers Java web app CWEs only. No agent/MCP vulnerability types. Uses Youden Index (single operating point) rather than threshold-independent comparison. Has not been extended to agent security despite scanner proliferation. |
| 2 | **MCP-SafetyBench (ICLR 2026)** — the strongest MCP security benchmark (20 attack types, 5 domains, multi-turn evaluation) | Evaluates MODEL safety, not SCANNER detection. Does not measure whether any scanning tool detects the vulnerabilities tested. No scanner comparison methodology. No FP analysis. The evaluation target is orthogonal to the practitioner's tool selection decision. |
| 3 | **Miercom DAST Benchmark 2026** — the most recent independent scanner evaluation (11 vulnerable apps, detection accuracy, independent validation) | Traditional web app focus only. Vendor-commissioned. No threshold-independent analysis (measures detection at single severity level). Methodology is sound but not applied to agent security tools. |

**Method import opportunities** (from §1b Adjacent Field Survey):

1. **Primary import — Manufacturing QA OC curves (ISO 2859-1):** Threshold-independent scanner comparison via Operating Characteristic curves. Maps producer risk (FP) and consumer risk (FN) on a common framework. Enables AOQL computation (worst-case vulnerability pass-through). Domain distance = 4 (different science). This is the core methodological contribution.

2. **Secondary import — Medical diagnostic test meta-analysis (Cochrane HSROC):** Bivariate model for handling sensitivity-specificity tradeoff when data is limited. QUADAS-2 adaptation for scanner evaluation study quality assessment. Domain distance = 4.

3. **Tertiary import — Mutation analysis (software testing):** Systematic ground-truth generation via vulnerability mutation operators. Contingency method if 30 CVEs prove insufficient for statistical power. Domain distance = 3.

**Gap type and design implication** (from §2 Gap Map):

**Tried in wrong domain (Gap 1) + Nobody tried (Gap 2):** The benchmarking methodology exists in traditional AppSec (OWASP Benchmark) but hasn't been transferred to agent security. The OC curve framework exists in manufacturing QA but hasn't been applied to any security scanner evaluation. This dual gap means the experimental approach must (a) construct the ground-truth corpus (domain transfer from OWASP Benchmark methodology), AND (b) implement OC curve analysis (method import from manufacturing QA). The design implication is a two-phase experiment: Phase 1 builds the benchmark infrastructure, Phase 2 runs the evaluation and computes OC curves.

**Landscape signals for design:**

| Signal | Status | Implication for experimental design |
|---|---|---|
| Benchmark/competition (§1.1) | **Absent for scanner evaluation** — exists for model evaluation | Creating the benchmark IS part of the contribution. Design must include corpus construction as a deliverable, not just analysis results. The benchmark artifact (ground-truth corpus + scoring framework) has independent value beyond the comparison results. |
| Evidence fragmentation (§2b) | **Severely fragmented** — incomparable metrics, populations, taxonomies, methodologies across all existing scanner data | Making evidence comparable via common ground truth + OC curves IS the contribution (Milkman pattern). Design must standardize: common server corpus, common taxonomy mapping, common output classification scheme, threshold-independent comparison metric. |

### §6b.1 Cross-Domain Mechanism Validity Pre-Check

<!-- gate:landscape mechanism_validity entries:1 -->

| Import | Core mechanism in source domain | Analog in target domain | Does mechanism OPERATE the same way? | Domain distance (1-5) | Evidence |
|---|---|---|---|---|---|
| **OC curves from manufacturing QA (ISO 2859-1)** | Acceptance sampling: inspector examines n items from lot of N, accepts if defects <= c. OC curve plots P(accept) vs true defect fraction p. Based on binomial/Poisson sampling statistics. Key assumption: defects are INDEPENDENT and identically distributed within a lot. | Scanner examines MCP server code/config, flags findings if matches >= threshold. OC analog plots P(pass scan) vs true vulnerability density. Based on scanner detection probability per vulnerability type. | **PARTIALLY — with important caveats.** (1) Independence assumption may FAIL: vulnerabilities in MCP servers are often correlated (e.g., eval() use causes multiple CWEs simultaneously). Manufacturing defects in a lot are typically independent. This is a meaningful mechanism difference. (2) Binary accept/reject maps cleanly to pass/fail scan. (3) "Defect rate" maps to "vulnerability density" only if vulnerabilities are countable and categorizable — contested for agent security (see §3 Contested items). (4) Lot size N and sample size n are well-defined in manufacturing but not in scanning (scanner examines 100% of code, not a sample). This means the SAMPLING aspect of OC curves doesn't transfer — but the DETECTION PROBABILITY aspect does. We use OC curves as a visualization of detection probability curves, not as sampling plans. | **4** (different science — manufacturing engineering → cybersecurity) | The mechanism transfer is valid for DETECTION PROBABILITY curves but NOT for SAMPLING PLANS. We are importing the OC curve as a representation format and producer/consumer risk framework, not the acceptance sampling methodology itself. This is honest: we don't sample MCP servers, we scan them entirely. The OC curve shape still characterizes scanner discrimination — steep = good scanner, flat = poor scanner — regardless of whether the underlying process involves sampling. The independence assumption violation should be pre-registered as a hypothesis: H_auxiliary = "vulnerability correlation within servers does not significantly distort OC curve shape compared to independent-defect assumption." |
| **HSROC from medical diagnostics (Cochrane)** | Hierarchical model accounts for threshold variation across studies. Assumes each study uses a different implicit threshold, causing negative sensitivity-specificity correlation. Fitted via bivariate random-effects model. Key assumption: studies are sampling from a common underlying ROC curve with study-level random effects. | Each scanner uses a different threshold/methodology. Our "studies" are scanners, not clinical trials. The bivariate model could account for threshold variation across scanners, analogous to across-study threshold variation. | **YES — mechanism operates the same way**, but our "studies" (scanners) are not random samples from a common population — they are engineered systems with deliberate design differences. The random-effects assumption is less justified. Fixed-effects comparison (each scanner gets its own curve) may be more appropriate, with HSROC reserved for aggregation if needed. | **4** (different science — clinical epidemiology → cybersecurity) | The mathematical framework transfers cleanly. The interpretive framework needs adaptation: in medicine, threshold variation is an artifact of study design; in our setting, threshold variation is a design choice by scanner developers. This distinction affects interpretation but not computation. |

---

## GPL-90: Structured Literature/Tool Enumeration

Before declaring the landscape scan complete, I enumerate categories that COULD be relevant:

| # | Category | Checked? | Result | If skipped, why? |
|---|---|---|---|---|
| 1 | MCP security benchmarks (model-focused) | YES | 3 found: MCP-SafetyBench, MSB, MCPSecBench. All model-focused, none scanner-focused. |  |
| 2 | Agent security scanner tools | YES | 9+ found: AgentSeal, Enkrypt AI, Cisco, MEDUSA, Sigil, Snyk, Ant Group MCPScan, mcpscan.ai, Microsoft AGT (runtime). |  |
| 3 | Traditional AppSec scanner benchmarks | YES | 2 found: OWASP Benchmark (ground-truth test suite), Miercom DAST Benchmark (independent evaluation). |  |
| 4 | SAST/DAST FP rate empirical studies | YES | 3 studies found: Ghost Security (91% FP), academic 815-commit study, Autonoma (40-60% FP). |  |
| 5 | MCP CVE/vulnerability databases | YES | 30+ CVEs in Jan-Feb 2026. NVD entries accessible. |  |
| 6 | MCP security taxonomies/frameworks | YES | 3 found: OWASP Agentic Top 10, MCP-DPT (defense placement), MCPSecBench (4 attack surfaces, 17 types). |  |
| 7 | Manufacturing QA / OC curve methodology | YES | ISO 2859-1, extensive literature on OC curve computation and interpretation. Well-established. |  |
| 8 | Medical diagnostic test evaluation methodology | YES | Cochrane DTA methodology, HSROC model, QUADAS-2. Mature field. |  |
| 9 | Mutation testing / fault injection | YES | Conceptual relevance confirmed for ground-truth scaling. No MCP-specific mutation operators found. |  |
| 10 | AI/LLM-based security scanning evaluation | PARTIAL | CTI-REALM (Microsoft, March 2026) evaluates AI agents for detection rule generation, not scanner comparison. No direct parallel found. | Searched but limited results for AI-evaluating-AI-scanner paradigm. |
| 11 | Agent red-teaming frameworks | SKIPPED | Tangentially relevant (red-teaming tests agent defenses, not scanner detection). | Out of scope: our question is about scanner effectiveness, not agent resilience. Cycle 1 already covers agent red-teaming. |
| 12 | Formal verification of MCP security | SKIPPED | arxiv 2604.05969 (formal security framework) found but focuses on formal proofs, not empirical scanner measurement. | Methodologically orthogonal — formal methods vs empirical measurement. |
| 13 | Commercial scanner evaluation reports (Gartner, Forrester) | SKIPPED | No agent-security-specific analyst reports found. Traditional AppSec MQ/Wave reports exist but don't cover agent scanners. | Category doesn't exist yet for agent security scanners — too new for analyst coverage. |

---

## §7 Landscape Gate Checklist

| # | Check | Status | Notes |
|---|---|---|---|
| 1 | Search protocol documented in §0 (databases, terms, date range) | [x] | 14 search terms across 7+ databases, date range 2024-2026 with methodology pre-2024 |
| 2 | >=5 prior works inventoried in §1 | [x] | 14 works inventoried with methodology, results, limitations, relevance |
| 3 | >=1 gap identified in §2 with type and evidence | [x] | 4 gaps identified with type, evidence, and opportunity size |
| 4 | Baseline knowledge state filled in §3 | [x] | Known/uncertain/contested documented with specific items |
| 5 | All 3 Frontier Moat Test questions answered in §4 | [x] | Novelty (0 similar), timing (5 enablers), moat (thin but timing-based) |
| 6 | Cross-engine context queried in §5 (not placeholder) | [x] | v_landscape_inputs queried, 2794 rows, key claims extracted |
| 7 | EDA readiness addressed in §6 (if computational) | [x] | Computational research type; 5 data sources listed; EDA scope defined; 3 data assumptions flagged as UNKNOWN |
| 8 | Mechanism validity assessed for each cross-domain import in §6b.1 | [x] | 2 imports assessed: OC curves (PARTIALLY — independence assumption violation noted), HSROC (YES with caveats) |
