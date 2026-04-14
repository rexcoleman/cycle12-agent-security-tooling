# Project: Agent Security Scanner Operating Characteristics

## Research Question

Do agent security scanners (AgentSeal, Cisco MCP Scanner, MEDUSA, and others) exhibit statistically distinguishable detection effectiveness when evaluated against a common ground-truth vulnerability corpus using Operating Characteristic curve methodology adapted from manufacturing quality assurance?

## Scope

- **In scope:** Comparative evaluation of open-source agent security scanners on a common ground-truth MCP vulnerability corpus. Construction of ground-truth test cases from public CVEs and MCPSecBench attack scripts. OC curve computation for threshold-independent comparison. Per-category detection profiling across OWASP Agentic AI risk categories. Scanner complementarity analysis (conditional on data quality).
- **Out of scope:** Runtime governance tools (Microsoft AGT — different category). Closed-source/commercial scanners without free access (Enkrypt AI, Snyk — unless freely accessible during EDA). Model safety benchmarking (already covered by MCP-SafetyBench, MSB, MCPSecBench). Scanner architecture analysis (HOW they work). New vulnerability discovery. Scanners for non-MCP agent frameworks.
- **Kill conditions:** (a) <15 classifiable test cases across >=3 OWASP categories — insufficient corpus for meaningful comparison. (b) <3 scanners produce parseable output on the corpus. (c) Scanner output cannot be mapped to TP/FP/TN/FN with kappa > 0.4 on manual review sample. (d) No scanner has configurable thresholds — OC curves collapse to single points (fallback: Youden-only comparison).

## Success Criteria

1. Ground-truth corpus of >=15 test cases (known-vulnerable + known-safe) across >=3 OWASP Agentic AI categories with binary labels
2. >=3 scanners evaluated on complete corpus with structured output parsed into TP/FP/TN/FN classifications
3. Per-scanner detection probability curves computed with 95% Clopper-Pearson confidence intervals
4. Pairwise scanner comparison with Fisher's exact test (p < 0.05 after Bonferroni correction)
5. Per-category detection heatmap showing scanner strengths and weaknesses
6. Publishable benchmark corpus + scoring framework as practitioner artifact

## Forbidden Proxies

- High scanner count does not count as thoroughness (3 deeply tested > 6 superficially tested)
- Many test cases does not count as coverage (15 well-labeled cases > 50 ambiguously labeled)
- Internal consistency of OC curves does not count as correctness (must validate against manual ground truth review)
- LLM self-assessment of vulnerability labels does not count as ground truth (CVE-backed labels required)
- Scanner vendor documentation does not count as detection evidence (must test empirically)

## Gap Analysis

**Gap:** No benchmark exists for comparing agent security scanner detection effectiveness. Three independent searches confirm: (a) arxiv "agent security scanner benchmark comparison" — 0 results targeting scanner evaluation. (b) GitHub "MCP scanner evaluation benchmark" — 0 benchmark projects found. (c) OWASP project pages — no agent-security extension of the OWASP Benchmark. Three MCP security benchmarks exist (MCP-SafetyBench ICLR 2026, MSB, MCPSecBench) but all evaluate model/agent behavior, not scanner tools. The methodological gap is dual: no ground-truth corpus for agent scanner evaluation (domain gap) AND no threshold-independent comparison framework for any security scanner domain (method gap).

**Why hasn't it been answered?** (a) Agent security scanners are 6-12 months old — the field hasn't had time to develop evaluation infrastructure. (b) The MCP security community benchmarked models (the thing being attacked) rather than scanners (the thing doing the detecting). (c) OC curve methodology from manufacturing QA has not been connected to security tool evaluation by any researcher.

## Significance

If this question is answered, practitioners choosing among 9+ agent security scanners get the first independent, threshold-independent comparison based on measured detection effectiveness against known vulnerabilities. They learn: which scanner catches which categories best, what false positive rates to expect, whether running multiple scanners is worth the overhead, and whether current scanning is "good enough" by manufacturing QA standards or effectively security theater. The benchmark corpus + scoring framework is reusable — new scanners can be evaluated by running them against the published corpus. The OC curve methodology for scanner evaluation is transferable to any domain with competing detection tools.

## Prior Work Engaged (minimum 3)

1. **OWASP Benchmark v1.2** (owasp.org/www-project-benchmark): Central claim — standardized ground-truth test suite enables objective SAST/DAST tool comparison. Methodology — 2,740 Java web app test cases with known-vulnerable/known-safe labels; Youden Index scoring (TPR - FPR). Key data — commercial tools range from Youden ~0.1 to ~0.7; many cluster near random (0.0); FP rates vary 10-80%. Relevance — direct methodological precedent; we build the agent-security equivalent and extend with OC curves for threshold-independent comparison.

2. **MCP-SafetyBench** (Xie et al., ICLR 2026, arxiv 2512.15163): Central claim — LLMs remain vulnerable to multi-turn MCP attacks, with negative defense-success/task-success tradeoff. Methodology — 20 attack types across 5 domains (browser, finance, navigation, repo mgmt, web search); multi-turn evaluation requiring multi-step reasoning. Key data — all models remain vulnerable; larger models not consistently safer; host-side attacks achieve highest success. Relevance — taxonomy source for ground-truth categories; confirms the threat landscape is real. Gap we address — evaluates model behavior, not scanner detection.

3. **Miercom DAST Benchmark 2026** (miercom.com): Central claim — independent third-party evaluation reveals significant detection gaps among commercial DAST tools. Methodology — 11 intentionally vulnerable apps (APIs, SPAs, GraphQL, traditional web); canonical vulnerability list + independently built validation apps; detection accuracy by severity. Key data — Invicti detected all 31 critical vulns; competitors missed 5-15 critical. Relevance — closest methodological analog for independent scanner evaluation with ground truth. Gap we address — covers traditional web apps only; no threshold-independent analysis.

4. **AgentSeal 1,808-server scan** (agentseal.org/blog, 2026): Central claim — 66% of MCP servers have security findings; 76 contain confirmed malicious payloads. Methodology — 4-layer pipeline (pattern detection, deobfuscation, semantic analysis, LLM judge) + red-teaming with 380+ attack probes; FP estimate of ~4.2% on 120 known-benign servers. Key data — largest published MCP scan; security scores for 800+ servers. Relevance — provides empirical anchor for what scanner findings look like at scale. Gap we address — self-reported, single-scanner, no cross-scanner comparison.
