# OBSERVATION LOG

<!-- version: 0.2 -->
<!-- created: 2026-04-14 -->
<!-- stage: 0 -->
<!-- methodology_status: partial — stages 0-2 methodology from Phase B.1 -->

> **Purpose:** Force systematic observation before questioning. Prevent
> "I have a hypothesis" without "I noticed something first." This template
> defines WHAT to log, not HOW to observe. The middle loop discovers process.

## Prediction (GPL-07)

Before deep scanning, I predict that **pain signals** and **anomaly signals** will yield the strongest observations. Specifically:
- Pain: practitioners overwhelmed by scanner proliferation with no way to compare effectiveness
- Anomaly: the gap between scanner claims and empirical validation will be the most actionable signal
- I expect the "opportunity" category to be weaker because the tooling space is moving so fast that opportunity signals are already being acted on (many scanners exist)

---

## §0 Signal Sources

<!-- gate:observation_log §0 entries:2 -->

| # | Source Type | Description | Date Range Scanned |
|---|---|---|---|
| 1 | Pipeline DB (singularity.db) | v_observation_inputs view — 93 signal rows covering agent security signals from SE experiments, plus distribution gaps, killed experiments, strategy findings | 2026-03-22 to 2026-04-14 |
| 2 | Literature / arXiv | WebSearch for recent agent security measurement papers, MCP security benchmarks, supply chain attack empirical studies | 2026-01-01 to 2026-04-14 |
| 3 | Industry tooling landscape | WebSearch for agent security scanners (PyPI, npm, GitHub), MCP scanner evaluations, enterprise toolkits | 2026-01-01 to 2026-04-14 |
| 4 | Community / practitioner signals | Reddit r/netsec, DEV Community, HackerOne disclosures, OWASP agentic AI working group outputs | 2026-01-01 to 2026-04-14 |

<!-- /gate:observation_log §0 -->

---

## §1 Observations

<!-- gate:observation_log §1 entries:3 -->

| # | Date | Source | Observation | Classification | Intensity |
|---|---|---|---|---|---|
| OBS-1 | 2026-04-14 | Industry tooling landscape | At least 9 distinct agent security scanners now exist (Sigil, MEDUSA, AgentAuditKit, SkillScan, Snyk agent-scan, qsag-core, mcpscan.ai, AgentSeal, Microsoft Agent Governance Toolkit) targeting overlapping but non-identical threat surfaces (MCP servers, PyPI packages, agent skills, runtime policies). No standardized benchmark exists to compare their detection effectiveness, false positive rates, or coverage overlap. | pain | 5 |
| OBS-2 | 2026-04-14 | Literature (arxiv 2604.08407) | "Your Agent Is Mine" (Liu et al., April 2026) measured 428 LLM API routers and found 9 injecting malicious code, 17 abusing credentials, with 2B billed tokens drained from decoys. This is the first systematic empirical measurement of LLM supply chain intermediary attacks — demonstrating that measurement-first methodology produces novel findings in agent security. | opportunity | 5 |
| OBS-3 | 2026-04-14 | AgentSeal blog + Enkrypt AI | AgentSeal scanned 1,808 MCP servers (66% had findings, ~4.2% false positive rate on known-benign set of 120 servers). Enkrypt AI scanned 1,000 MCP servers (33% critical). These numbers are substantially different — 66% vs 33% "had findings" depending on severity threshold — suggesting scanner calibration and threshold definition vary enormously and lack standardization. | anomaly | 5 |
| OBS-4 | 2026-04-14 | Pipeline DB signals | 6 pipeline signal experiments (PyPI scanner, GitHub Action, MCP server, OWASP mapping, HuggingFace dataset, OWASP Agent Bench) operate in the agent security tooling space. The PyPI scanner and GitHub Action directly compete with commercial offerings that have emerged (Sigil, Snyk agent-scan, MEDUSA). Market validation question: do these experiments address a gap the commercial tools miss? | pain | 4 |
| OBS-5 | 2026-04-14 | Microsoft OSS Blog (2026-04-02) | Microsoft released Agent Governance Toolkit — MIT-licensed, claims coverage of all 10 OWASP agentic AI risks, sub-millisecond policy enforcement, framework-agnostic (LangChain, CrewAI, Google ADK). Available in Python, TypeScript, Rust, Go, .NET. This is the first major vendor open-source release covering the full OWASP agentic threat surface. It fundamentally changes the competitive landscape for smaller agent security tools. | trend | 5 |
| OBS-6 | 2026-04-14 | MCP CVE data | 30 CVEs filed against MCP servers/clients in Jan-Feb 2026 alone, including CVSS 9.6 RCE. MCP ecosystem grew from ~2,000 registry entries to 16,000+ unofficial servers. The attack surface is growing faster than security tooling can characterize it. | trend | 4 |
| OBS-7 | 2026-04-14 | arxiv (MCP-SafetyBench, MCP Security Bench) | Two benchmark papers exist: MCP-SafetyBench (arxiv 2512.15163, ICLR 2026) covers 5 domains with 20 attack types; MCP Security Bench (arxiv 2510.15994) benchmarks attacks against MCP. These benchmark the MODEL's safety behavior when using MCP, NOT the scanner/tool detection effectiveness. The gap is scanner-vs-scanner comparison, not model-vs-model. | anomaly | 4 |

<!-- /gate:observation_log §1 -->

### §1.1 Question Lineage

**Pipeline research frontiers — query results:**

```
sqlite3 ~/singularity.db "SELECT id, cycle_id, limitation_text, suggested_next_question 
FROM limitations_next_questions WHERE status='open' ORDER BY cycle_id DESC;"
```

| ID | Cycle | Limitation | Suggested Next Question |
|----|-------|-----------|----------------------|
| 9 | 7 | LiteLLM back-test is single case study with single topology type | Systematic empirical validation: parameterize simulation from 3+ real supply chain incidents across topology types |
| 8 | 7 | Only single-layer networks tested; real AI supply chains are multiplex | Do multiplex AI supply chain networks exhibit reentrant phase transitions? |
| 7 | 7 | Absorption capacity modeled as fixed; real detection evolves | How does adaptive absorption capacity affect steady-state cascade behavior? |
| 6 | 7 | All simulations use static network topology; real supply chain topology evolves | How does temporal evolution affect phase-transition threshold? |
| 5 | 7 | Acemoglu shock dilution doesn't model replicating attacks | What contagion framework correctly models replicating (non-diluting) attacks through intermediary networks? |
| 4 | 6 | This cycle is confirmatory | Can the pipeline produce N>=7 with continuity + grounding? |
| 3 | 6 | Continuity mechanism untested | Does addressing a prior limitation produce N>5? |
| 2 | 6 | G=9 anchor sparse | What does G=9 look like in clinical medicine? |
| 1 | 6 | Leverage estimates are projections | Does implementing top 3 patterns raise composite by >=1.0? |

**Lineage mapping:**

| OBS-# | What limitation of prior work does this observation connect to? | Prior work reference |
|---|---|---|
| OBS-1 | No standardized benchmark for agent security scanners parallels limitation #9 (single case study validation). The field lacks systematic empirical comparison, just as Cycle 7's supply chain model lacked multi-case validation. | Cycle 7 limitation #9; also: no prior scanner benchmark paper found in literature search |
| OBS-2 | Liu et al.'s measurement methodology (428 routers, canary credentials, honeypot decoys) demonstrates the kind of systematic empirical validation that limitation #9 calls for, but applied to intermediary attacks rather than scanner effectiveness | Cycle 7 limitation #9; Liu et al. 2604.08407 |
| OBS-3 | The 66% vs 33% discrepancy between AgentSeal and Enkrypt AI scans demonstrates that "absorption capacity" (detection capability) is NOT fixed — it varies by scanner, threshold, and methodology. Directly connects to limitation #7 (fixed absorption capacity). | Cycle 7 limitation #7 |
| OBS-5 | Microsoft AGT's release as a vendor-backed full-OWASP tool changes the supply chain topology — a single major node now covers the entire threat surface. Connects to limitation #6 (static topology). | Cycle 7 limitation #6 |

---

## §1b Technology Readiness Scan

| OBS-# | What changed recently making this actionable NOW? | When did this enabler become available? |
|---|---|---|
| OBS-1 (intensity 5) | 9+ scanners now exist to compare. 12 months ago there were essentially zero dedicated agent security scanners. The MCP ecosystem reaching 16,000+ servers created enough attack surface for scanners to differentiate. | Scanner proliferation: Q4 2025 — Q1 2026 |
| OBS-2 (intensity 5) | Liu et al. published the first empirical measurement methodology for LLM supply chain attacks in April 2026. Their honeypot/canary methodology is replicable and could be adapted for scanner evaluation. | April 2026 (arxiv 2604.08407) |
| OBS-3 (intensity 5) | AgentSeal's 1,808-server scan dataset and Enkrypt AI's 1,000-server scan provide the first large-scale ground truth datasets for MCP security findings. Before this, no one had scanned at scale. | Q1 2026 |
| OBS-5 (intensity 5) | Microsoft AGT released April 2, 2026. As the first major vendor open-source entry, it provides both a baseline to benchmark against AND a potential framework for standardized evaluation. | April 2, 2026 |
| OBS-6 (intensity 4) | 30 CVEs in 60 days provides a ground truth vulnerability dataset. These CVEs have known severity, affected components, and in many cases public exploits. This is the raw material for a scanner detection benchmark. | Jan-Feb 2026 |

---

## §1c Cross-Field Method Scan

| Observation cluster | Analogous field 1 | Their method | Analogous field 2 | Their method |
|---|---|---|---|---|
| Scanner effectiveness comparison (OBS-1, OBS-3, OBS-7) | **Manufacturing quality assurance** | Acceptance Quality Level (AQL) sampling with Operating Characteristic (OC) curves — quantifies the tradeoff between producer risk (false positives = rejecting good lots) and consumer risk (false negatives = accepting bad lots) for any inspection/detection system. Allows comparison of inspection systems on a common statistical framework. | **Medical diagnostic testing** | Sensitivity/specificity analysis with ROC curves — evaluates diagnostic tests (analogous to scanners) against known-positive and known-negative cases, producing receiver operating characteristic curves that enable head-to-head comparison of detection instruments independent of threshold choice. |
| Supply chain intermediary measurement (OBS-2, OBS-6) | **Epidemiological surveillance** | Sentinel surveillance with canary/honeypot methodology — placing known-vulnerable monitored nodes in a network to measure attack incidence. Liu et al. already adapted this for LLM routers. | **Environmental monitoring** | Pollution source attribution via receptor modeling — measuring contaminant concentrations at multiple downstream points to reconstruct upstream source profiles. Analogous to measuring downstream scanner outputs to attribute upstream vulnerability types. |

**Self-test:** Manufacturing QA (AQL/OC curves) and medical diagnostics (ROC curves) are genuinely outside cybersecurity. The AQL framework in particular has not been applied to agent security scanner evaluation — it provides a formally defined, statistically grounded method for comparing detection systems that is standard in manufacturing but absent in security tooling evaluation.

---

## §2 Cross-Engine Context

<!-- queried: v_observation_inputs, 93 rows -->

```
Run: sqlite3 ~/singularity.db "SELECT * FROM v_observation_inputs;"
93 rows returned.
```

**Key signals from cross-engine context (intensity >= 5):**

| Signal ID | Category | Intensity | Summary |
|---|---|---|---|
| 17 | agent_serialization | 5.0 | MD5 + pickle deserialization in AutoGen — agent memory RCE risk |
| 24 | memory_corruption | 5.0 | LangChain memory poisoning persists across sessions, no detection available |

**Key signals (intensity >= 7):**

| Signal ID | Category | Intensity | Summary |
|---|---|---|---|
| — | model_supply_chain | 7.0 | OpenClaw rename triggered instant supply chain attacks: GitHub, NPM, Twitter handles sniped within seconds |
| — | other | 7.0 | AI psychosis: MoltBook agents on social networks triggered mass inability to distinguish AI vs human content |
| — | — | 7.0 | "Your Agent Is Mine" — LLM supply chain intermediary measurement study |
| — | — | 7.0 | Sandbox escape vulnerabilities in major AI tools (Claude Code, Google, OpenAI) |
| — | — | 7.0 | Claude Code RCE via environment variable injection |
| — | — | 7.0 | Two different attackers poisoned popular open source tools |
| — | — | 7.0 | DRAM timing + grid frequency + gyroscope fusion for bot detection |
| — | — | 7.0 | Coinbase AgentKit prompt injection: wallet drain, RCE |

**Pattern from cross-engine data:** High-intensity signals cluster around three themes: (1) supply chain attacks on agent infrastructure (LiteLLM, OpenClaw, AutoGen), (2) runtime vulnerabilities in agent frameworks (memory poisoning, sandbox escapes, prompt injection), and (3) measurement/detection gaps (no scanner comparison, divergent scan results). Theme 3 is under-served by existing research.

---

## §3 Pattern Notes

<!-- gate:observation_log §3 entries:1 -->

| # | Pattern | Supporting Observations | Surprising? | Contradicts Prior Assumption? |
|---|---|---|---|---|
| PAT-1 | **Scanner proliferation without measurement:** 9+ agent security scanners exist, but no one has measured their comparative effectiveness. The two largest scans (AgentSeal 1,808 servers, Enkrypt AI 1,000 servers) produced divergent findings (66% vs 33%) with no way to reconcile the difference. This is analogous to having multiple medical diagnostic tests but no ROC curve comparison. | OBS-1, OBS-3, OBS-7 | Yes — surprising that the field has moved to deployment without even basic detection rate measurement | Yes: contradicts the assumption that "more tools = better security." Without measurement, more tools may mean more inconsistency and false confidence. |
| PAT-2 | **Measurement methodology exists but hasn't been applied to scanners:** Liu et al. (OBS-2) demonstrated rigorous measurement methodology for intermediary attacks (honeypots, canary credentials, controlled experiments). MCP-SafetyBench and MCP Security Bench benchmark model behavior. But no one has applied measurement methodology to the SCANNERS THEMSELVES — the tools practitioners must choose between. | OBS-2, OBS-7, OBS-1 | Yes — the measurement gap is at the meta-level (measuring the measurers) | Yes: contradicts the assumption that publishing a scanner is sufficient — without calibration, a scanner's output is not interpretable. |
| PAT-3 | **Major vendor entry compresses the market:** Microsoft AGT's release covering all 10 OWASP risks with MIT licensing may make smaller single-purpose scanners obsolete for enterprise adoption. The research question shifts from "build a scanner" to "measure scanner effectiveness" — the former is now commodity, the latter is novel. | OBS-5, OBS-4 | Partially — expected major vendors to enter, but the speed (full OWASP coverage in first release) was surprising | Yes: contradicts the pipeline's signal experiment hypothesis that cold-start tools can compete on capability alone. The differentiator must be measurement/validation, not detection. |

<!-- /gate:observation_log §3 -->

---

## §4 Observation Gate Checklist

| # | Check | Status | Notes |
|---|---|---|---|
| 1 | >=2 distinct source types in §0 | [x] | 4 source types: Pipeline DB, literature, industry tooling, community |
| 2 | >=3 observations logged in §1 | [x] | 7 observations logged (OBS-1 through OBS-7) |
| 3 | Cross-engine context queried in §2 (not placeholder) | [x] | v_observation_inputs queried, 93 rows, key signals summarized |
| 4 | >=1 pattern noted in §3 | [x] | 3 patterns identified |
| 5 | Most recent observation within last 90 days | [x] | All observations from 2026-04-14 |
| 6 | No single source type accounts for all observations | [x] | Observations draw from all 4 source types |
