# Requirements: Agent Security Scanner Operating Characteristics

## Deliverables

1. **FINDINGS.md** — govML-compatible, CLAIM_STRENGTH_SPEC tagged, with all required sections (Novelty Assessment, Cross-Domain Connections, Generalization Analysis, Practitioner Impact, Hostile Baseline Check, Effect Persistence, Boundary Statement, Pre-emptive Criticism)
2. **Ground-truth MCP vulnerability corpus** — structured test cases (known-vulnerable + known-safe MCP server configurations) with labels, OWASP category mapping, and CVE/source traceability. Output: `outputs/corpus/` directory with test case manifests.
3. **Scanner evaluation data** — raw scanner outputs per test case per scanner. Output: `outputs/scanner_results/` directory with structured JSON per scanner.
4. **Detection profiles** — per-scanner, per-category detection rates with confidence intervals. Output: `outputs/analysis/detection_profiles.csv`
5. **OC curve data and visualizations** — detection probability curves per scanner (if threshold-configurable) or Youden comparison (if not). Output: `outputs/figures/`
6. **Scoring framework script** — `scripts/score_scanner.sh` that runs any scanner against the corpus and computes detection metrics. Practitioner-facing artifact.
7. **EXECUTION_PROTOCOL.md** — filled DURING execution (not backfilled), documenting runtime quality gates, deviations, measurement protocol.

## Quality Requirements

- Minimum depth budget: 5 distinct primary sources substantively engaged (OWASP Benchmark, MCP-SafetyBench, Miercom DAST Benchmark, AgentSeal blog, ISO 2859-1 OC curve methodology)
- Minimum sources: 8 distinct primary sources cited in FINDINGS.md
- 100% claims tagged per CLAIM_STRENGTH_SPEC
- Hostile baseline check must SURVIVE (hostile reviewer simulation)
- Novelty Assessment differentiates from 5+ prior works (OWASP Benchmark, MCP-SafetyBench, MSB, MCPSecBench, Miercom DAST Benchmark)
- All paper titles verified via WebSearch before citing
- Per-category results reported with exact confidence intervals (Clopper-Pearson)
- Inter-rater agreement on ground-truth labels: kappa > 0.6 on 20% manual review sample
- OC curves (or Youden comparison if threshold kill condition triggered) computed for all evaluated scanners

## Constraints

- Single research cycle (EDA + corpus construction + scanner execution + analysis + writing)
- Computational experiment: scanner installation and execution on Mac Mini (48GB, M4 Pro); analysis and writing on Azure (7.7 GiB)
- Open-source scanners only (reproducibility requirement)
- Ground-truth labels must be traceable to CVEs, MCPSecBench attacks, or OWASP taxonomy
- EDA phase must validate 3 critical unknowns before committing to full methodology: (a) CVE-to-test-case conversion feasibility, (b) scanner output format mappability to TP/FP/TN/FN, (c) scanner threshold configurability
- Scanner execution: 3 runs per test case for stochastic scanners (LLM-judge components); 1 run for deterministic scanners
- All statistical analyses specified in ED Statistical Plan must be executed (execution fidelity per process_changes from prior cycles)
- Generalization Analysis section mandatory (process_changes: G consistently below threshold without explicit boundary statements)
