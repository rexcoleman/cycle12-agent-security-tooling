# HYPOTHESIS REGISTRY

> **Project:** Agent Security Scanner Operating Characteristics
> **Created:** 2026-04-14
> **Status:** PRE-REGISTERED
> **Lock commit:** TBD

## H-1: Primary — Scanner Distinguishability

| Field | Value |
|-------|-------|
| **Statement** | Agent security scanners (AgentSeal, Cisco MCP Scanner, MEDUSA, and at least 1 additional open-source scanner) exhibit statistically distinguishable detection effectiveness (pairwise Fisher's exact test p < 0.05 after Bonferroni correction) when evaluated against a common ground-truth MCP vulnerability corpus of >=15 test cases across >=3 OWASP Agentic AI categories. |
| **Prediction** | At least 1 scanner pair will show significantly different overall Youden Index scores. Scanners will show greater divergence in semantic vulnerability categories (prompt injection, tool poisoning) than syntactic categories (code injection, path traversal). |
| **Falsification** | REFUTED if: no scanner pair achieves significant detection difference after Bonferroni correction on the full corpus, AND per-category analysis also shows no significant differences. This would mean scanners are functionally equivalent on known vulnerabilities. |
| **Surprise criteria** | **Would surprise scanner developers:** if ALL scanners perform near-random (Youden < 0.1) on ALL categories. **Would surprise security researchers:** if ONE scanner dominates ALL categories (Youden > 0.5 everywhere while others are < 0.2). Named experts: Dave Bittner (CyberWire, covers scanner market), Niko Lehto (AgentSeal founder, whose tool's claims would be directly tested). |
| **Status** | PENDING |
| **Linked Experiment** | ED Phase 3: Scanner evaluation + OC curve computation |
| **lock_commit** | TBD |

## H-2: Secondary — Scanner Specialization Pattern

| Field | Value |
|-------|-------|
| **Statement** | Scanner detection profiles show category-level specialization: each scanner's highest-detection category differs from at least 1 other scanner's highest-detection category, as measured by per-category Youden Index ranking. |
| **Prediction** | AgentSeal (multi-layer + LLM judge) will lead on semantic categories (prompt injection). Cisco (YARA + behavioral) will lead on syntactic categories (code injection). Sigil (supply-chain focus) will lead on dependency/supply-chain categories but near-zero elsewhere. |
| **Falsification** | REFUTED if: all scanners share the same highest-detection category AND the same lowest-detection category (uniform non-specialization). |
| **Surprise criteria** | **Genuine surprise:** if a simple rule-based scanner (e.g., MEDUSA with YARA rules) outperforms LLM-judge scanners on semantic vulnerability categories — this would contradict the assumption that semantic analysis requires semantic tools. |
| **Status** | PENDING |
| **Linked Experiment** | ED Phase 3: Per-category detection heatmap |
| **lock_commit** | TBD |

## H-3: Auxiliary — Independence Assumption (Pre-registered per LA §6b.1)

| Field | Value |
|-------|-------|
| **Statement** | Vulnerability correlation within MCP servers (e.g., eval() use causing multiple CWEs simultaneously) does not significantly distort per-scanner detection probability estimates compared to an independent-defect assumption. Specifically: detection rate estimates computed under independence differ by less than 10 percentage points from estimates computed using clustered bootstrap (resampling at server level rather than vulnerability level). |
| **Prediction** | Moderate distortion (5-15 percentage points) for code injection categories where eval() creates correlated vulnerabilities; minimal distortion (<5 pp) for categories with diverse root causes. |
| **Falsification** | REFUTED if: clustered bootstrap estimates differ by >10 percentage points from independence estimates for >=50% of scanner-category pairs. This would mean OC curve methodology requires cluster-corrected computation for validity. |
| **Surprise criteria** | **Would surprise manufacturing QA specialists:** if independence assumption holds well (distortion < 5pp across all categories) — this would mean vulnerability occurrence is less correlated than manufacturing defects, reversing the expected direction of the mechanism validity concern. |
| **Status** | PENDING |
| **Linked Experiment** | ED Phase 3 sensitivity analysis: independence vs clustered bootstrap |
| **lock_commit** | TBD |

## H-4: Secondary — AOQL and Scanner Complementarity (Conditional on sufficient data quality)

| Field | Value |
|-------|-------|
| **Statement** | The Average Outgoing Quality Limit (AOQL) — the worst-case vulnerability density that passes through a scanner undetected — differs by >=2x between the best and worst tested scanners. Furthermore, running the top-2 scanners in series reduces AOQL by >=30% compared to the best single scanner alone. |
| **Prediction** | Best single-scanner AOQL will be 0.15-0.30 (15-30% of vulnerabilities pass through undetected). Running 2 scanners in series will reduce to 0.10-0.20. Diminishing returns beyond 2 scanners. |
| **Falsification** | REFUTED if: AOQL difference between best and worst scanner is <2x (scanners are calibrated similarly), OR running 2 scanners in series reduces AOQL by <10% (scanners have overlapping, not complementary, blind spots). |
| **Surprise criteria** | **Would surprise practitioners:** if running ANY single scanner achieves AOQL < 0.05 (catching 95%+ of vulnerabilities) — this would mean the "multi-scanner strategy" popular in enterprise security is unnecessary for agent security. |
| **Status** | CONDITIONAL — activated only if corpus size >=20 AND per-scanner detection rates are estimable with CI width < 0.3 |
| **Linked Experiment** | ED Phase 3b: AOQL computation (conditional) |
| **lock_commit** | TBD |

## Resolution Log

| ID | Status | Evidence | Date |
|----|--------|----------|------|
| H-1 | PARTIALLY SUPPORTED | 2 of 3 scanner pairs significantly different (Cisco vs Sigil p<0.001, MEDUSA vs Sigil p<0.001 after Bonferroni). Cisco vs MEDUSA NOT significant (p=0.667). | 2026-04-14 |
| H-2 | PARTIALLY SUPPORTED | Category-level profiles differ (ASI01=0% all scanners, ASI05=100% Sigil). Predicted specialization pattern wrong: Sigil led all categories, no scanner led semantic categories. | 2026-04-14 |
| H-3 | SUPPORTED | Each test case is independent server. Clustered bootstrap = standard bootstrap. No distortion. | 2026-04-14 |
| H-4 | PARTIALLY SUPPORTED | AOQL ratio 23x (exceeds 2x threshold). Complementarity REFUTED: multi-scanner union = Sigil alone. Detection sets nested, not complementary. | 2026-04-14 |
