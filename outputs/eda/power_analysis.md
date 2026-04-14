# Statistical Power Estimation — Phase 1 EDA (Task 5)

## Input Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| CVEs found (Jan-Apr 2026) | 26 | Task 1 NVD/GitHub search |
| Reproducible/partially reproducible | 17/9 | Task 1 classification |
| MCPSecBench supplementation (high feasibility) | 7 attack types | Task 2 inventory |
| Estimated vulnerable test cases after supplementation | ~24 | 17 reproducible CVEs + 7 MCPSecBench |
| Safe control cases (planned) | 10 | ROADMAP Phase 2 |
| Total corpus estimate | ~34 | 24 + 10 |
| Working scanners | 4 | AgentSeal, Cisco, MEDUSA, Sigil |
| Scanner pairs for comparison | 6 | C(4,2) |
| OWASP categories with cases | 6 | Task 1 classification |

## (a) Power for Overall Fisher's Exact Test

Power computed at significance level alpha=0.05 (two-sided), comparing detection rates between scanner pairs, assuming base detection rate p1=0.70.

| N (vulnerable cases) | Effect size (rate difference) | Power |
|---------------------|------------------------------|-------|
| 15 | 0.30 | 0.373 |
| 20 | 0.30 | 0.478 |
| 24 | 0.30 | 0.554 |
| 30 | 0.30 | 0.653 |
| 34 | 0.30 | 0.710 |

**Interpretation:** At N=24 vulnerable cases and effect size 0.30, power is 0.554 (underpowered for conventional 0.80 threshold). Power reaches 0.71 at N=34. The study is designed to detect LARGE differences between scanners (effect >= 0.40) with adequate power, but may miss moderate differences (effect 0.20-0.30).

## (b) Minimum Detectable Effect Size

At 80% power, the minimum detectable effect size for N=24 vulnerable cases:

| Base detection rate | MDE (for 80% power) |
|--------------------|---------------------|
| 0.70 | 0.395 |
| 0.80 | 0.385 |

**Interpretation:** With N=24, we can only reliably detect differences of ~40 percentage points between scanners. This is a large effect — e.g., Scanner A detects 80% of vulnerabilities while Scanner B detects 40%. This is realistic for our use case based on EDA: Cisco scanner detected 2/3 vulnerable tools while MEDUSA's generic findings couldn't distinguish vulnerable from safe, suggesting large performance differences may exist.

## (c) Per-Category vs Supercategory Feasibility

### Raw category case counts

| OWASP Category | Case Count | Statistical Analysis |
|---------------|-----------|---------------------|
| ASI05 Unexpected Code Execution | 12 | Inferential (Fisher's exact) |
| ASI03 Identity and Privilege Abuse | 5 | Inferential (borderline, low power) |
| ASI04 Agentic Supply Chain Vulnerabilities | 4 | Descriptive only |
| ASI01 Agent Goal Hijack (from MCPSecBench) | 4 | Descriptive only |
| ASI02 Tool Misuse | 3 | Descriptive only |
| ASI07 Insecure Inter-Agent Communication | 1 | Not analyzable |

### Supercategory aggregation (recommended)

| Supercategory | Components | Case Count | Analysis |
|--------------|-----------|-----------|----------|
| Injection-class | ASI01 + ASI05 | 16 | Inferential |
| Access-control-class | ASI03 | 5 | Inferential (low power) |
| Supply-chain-class | ASI04 | 4 | Descriptive |

**Recommendation:** Use 2 supercategories (Injection-class, Access-control-class) for primary inferential analysis. Report remaining categories descriptively. This aligns with ROADMAP requirement of >=3 categories — we have 3 with cases but only 2 reach inferential thresholds.

### Bonferroni correction

- Total comparisons: 18 (6 scanner pairs x 2 inferential categories + 6 overall)
- Corrected alpha: 0.0028
- This strict correction further reduces power. Consider: report both uncorrected and Bonferroni-corrected p-values, flag discrepancies.

### Confidence interval widths (Clopper-Pearson 95%)

| N | Observed k | Rate | CI | Width |
|---|-----------|------|-----|-------|
| 24 | 17 | 0.71 | [0.489, 0.874] | 0.385 |
| 24 | 12 | 0.50 | [0.291, 0.709] | 0.418 |
| 10 | 8 | 0.80 | [0.444, 0.975] | 0.531 |
| 5 | 3 | 0.60 | [0.147, 0.947] | 0.801 |

**Interpretation:** CI widths are wide (0.38-0.80). Per-category analysis with N=5 has CI width 0.80 (uninformative). Overall analysis with N=24 has CI width 0.39 (marginally useful).

## AOQL Feasibility

Phase 3b activation condition: corpus >= 20 AND per-scanner CI width < 0.3.

- With N=24: CI width ~0.39 (exceeds 0.3 threshold)
- With N=34: CI width ~0.31 (borderline)
- **Assessment:** AOQL computation is BORDERLINE. May require supercategory aggregation or larger corpus from Phase 2 supplementation to meet CI width < 0.3 criterion.

## Summary and Implications

1. **Overall comparison is FEASIBLE** — Fisher's exact test can detect large differences (>= 0.40) between scanners with adequate power at N=24.
2. **MDE is large** (~0.40) — the study is designed as a discrimination test, not a precision measurement. This is appropriate for the research question ("are scanners distinguishable?") but limits claims about small differences.
3. **Per-category analysis is LIMITED** — only 2 supercategories support inferential analysis. This narrows the contribution compared to the full per-category vision.
4. **AOQL is BORDERLINE** — H-4 (AOQL hypothesis) may not be testable with current corpus size. This was anticipated in ED as a conditional hypothesis.
5. **Practical significance threshold:** Given CI widths of 0.39, differences smaller than ~20 percentage points will be statistically invisible. Focus claims on large, practitioner-visible differences.
