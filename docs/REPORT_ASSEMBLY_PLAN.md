# REPORT ASSEMBLY PLAN

<!-- version: 1.0 -->
<!-- created: 2026-02-20 -->
<!-- last_validated_against: CS_7641_Machine_Learning_OL_Report -->

> **Authority hierarchy:** {{TIER_1_SOURCE}} (Tier 1) > {{TIER_2_SOURCE}} (Tier 2) > {{TIER_3_SOURCE}} (Tier 3) > This document (Contract)
> **Conflict rule:** When a higher-tier document and this contract disagree, the higher tier wins. Flag the conflict in the DECISION_LOG.
> **Upstream:** FINDINGS (resolved hypothesis narratives and evidence), HYPOTHESIS_REGISTRY (hypothesis statements for report sections), FIGURES_TABLES_CONTRACT (figure/table definitions), METRICS_CONTRACT (summary table interface)
> **Downstream:** REPORT_CONSISTENCY_SPEC (cross-section consistency validation), PRE_SUBMISSION_CHECKLIST (report content audit)

{{PROJECT_NAME}} — Report Assembly Plan

---

## 1) Purpose & Report Constraints

This document provides the plan for assembling the final report. Every decision traces to the authority hierarchy.

**Hard constraints:**

| Constraint | Source | Penalty |
|---|---|---|
| Max {{PAGE_LIMIT}} pages (including figures + references) | *(cite)* | Content past limit not reviewed |
| Written in {{FORMAT}} on {{PLATFORM}} | *(cite)* | Required format |
| READ-ONLY link in report or delivery | *(cite)* | Non-compliance |
| Paragraph prose; analysis MUST NOT be bullet lists | *(cite)* | Non-compliance |
| Two deliverables: Report + REPRO | *(cite)* | Incomplete delivery |
| At least {{MIN_REFS}} peer-reviewed references | *(cite)* | Non-compliant |
| AI Use Statement | *(cite)* | Non-compliant |
| Single citation style | *(cite)* | Non-compliance |

---

## 2) Section Outline & Page Budget

| Section | Content | Budget |
|---|---|---|
| Title / Abstract | Title, authors, optional abstract (~150 words) | 0.25 |
| 1. Introduction | Problem, gap, what report does | 0.50 |
| 2. Data & EDA | Datasets, metrics, preprocessing, EDA summary | 0.50 |
| 3. Hypotheses | One per dataset, before experiments | 0.30 |
| 4. Methods | Splits, budgets, seeds, hardware, architecture | 0.75 |
| 5-N. Results | One section per experimental part | *(allocate)* |
| Conclusion | Accept/reject hypotheses, decision rule, limitations | 0.50 |
| AI Use Statement | Per template | 0.10 |
| References | Peer-reviewed sources | 0.40 |
| | **Total** | **~{{TOTAL}}** |

*(The margin accommodates figures, tables, and float placement.)*

---

## 3) Writing Rules

### Results Sections (CRITICAL)

- MUST be paragraph prose with coherent reasoning
- Every figure/table reference MUST include a takeaway
- Results structured around testing hypotheses, not merely reporting
- **CCC paragraph structure:** Context (what question) → Content (evidence) → Conclusion (what it means)
- Logical thread: each section opens by connecting to the previous section's key finding

### Hypotheses

- Written as prose paragraphs
- Stated before experiments (not retroactive)
- Include: prediction, reasoning from EDA, optimization/ML mechanism, baseline prediction

### Methods

- Bullets acceptable for hyperparameter lists and protocol steps
- Rationale for design choices in prose

### Central Contribution (Rule of One)

Before writing, identify the single most important finding that ties all parts together. Craft the title to convey this finding. Every section should advance this central thread.

---

## 4) Figure & Table Placement

*(Map each figure/table to its report section and interpretation goal.)*

| ID | Title | Section | What to Interpret |
|----|-------|---------|-------------------|
| F1 | *(title)* | *(section)* | *(interpretation goal)* |
| T1 | Summary Table | Before Conclusion | Side-by-side comparison of all methods |
| *(add rows)* | | | |

---

## 5) Baseline Comparison Requirement

Every intervention MUST be explicitly compared to the baseline, stating improved / not improved / conditionally improved.

**Template:**

> Compared to the baseline ({{BASELINE_METRIC_NAME}} = {{BASELINE_VALUE}}), [method] achieved a median {{METRIC}} of Y.YYY (IQR: [a, b]) under [budget], representing a [+/-]Z.ZZZ absolute change. This [improvement / non-improvement] is [attributable to / explained by] [mechanism].

---

## 6) Hypothesis Templates

### Statement (Section 3)

> **Hypothesis ({{DATASET}}):** Based on [EDA observation], I predict that [specific behavior], because [mechanism]. Relative to the baseline ({{METRIC}} = X.XXX), I predict that [intervention] will [improve / not improve] because [reasoning].

### Resolution (Conclusion)

> **Resolution ({{DATASET}}):** The hypothesis predicted [summary]. Experiments showed [observed result: median = Y.YYY, IQR = [a, b], under Z evals]. [Accept / Reject]: the prediction was [supported / contradicted] because [quantitative evidence]. The compute cost was [budget], suggesting [practical implication].

---

## 7) References Plan

At least {{MIN_REFS}} peer-reviewed references, used substantively (not just listed).

| Category | Purpose | Example Topics |
|---|---|---|
| *(e.g.)* Optimizer theory | Justify ablation design | Adam, AdamW |
| *(e.g.)* Regularization | Justify technique selection | Dropout, label smoothing |
| *(e.g.)* Evaluation metrics | Justify metric choices | F1 for imbalanced data |
| *(add rows)* | | |

**Rules:**
- Do NOT fabricate citations
- Every source MUST be used substantively in report text
- One consistent citation style throughout

---

## 8) REPRO Document Checklist

The REPRO document MUST contain:

- [ ] READ-ONLY link to report
- [ ] Git commit SHA from final push
- [ ] Exact run commands for all scripts
- [ ] Environment setup commands
- [ ] Data paths and acquisition instructions
- [ ] Random seeds (default + stability list)
- [ ] EDA summary confirmation per dataset
- [ ] Output directory structure

---

## 9) Pre-Flight Checklist

### Report Content

- [ ] **CRITICAL:** Page count within limit
- [ ] **CRITICAL:** Paragraph prose in results/discussion
- [ ] **CRITICAL:** READ-ONLY link present
- [ ] AI Use Statement present
- [ ] Sufficient peer-reviewed references
- [ ] Consistent citation style
- [ ] Hypotheses stated before experiments
- [ ] Hypotheses resolved with quantitative evidence

### Figures & Tables

- [ ] **CRITICAL:** All required figures present
- [ ] **CRITICAL:** All required tables present
- [ ] Every figure/table referenced with interpretation
- [ ] Summary table has required columns + baseline row
- [ ] Captions include takeaways

### Evaluation Discipline

- [ ] **CRITICAL:** Dispersion shown (not just means)
- [ ] **CRITICAL:** Budgets matched across compared methods
- [ ] **CRITICAL:** Test set used exactly once
- [ ] Generalization gap reported
- [ ] Sanity checks reported
- [ ] Failures explained

### Baseline & Decision

- [ ] **CRITICAL:** Baseline comparison per dataset
- [ ] Decision rule / practical recommendation in conclusion

### Delivery

- [ ] Two deliverables (Report + REPRO)
- [ ] Code pushed to designated repository
- [ ] Commit SHA matches REPRO
- [ ] Delivered by delivery date

---

## Statistical Results Reporting Template

> **LL-78 guidance:** All quantitative claims must follow consistent statistical reporting. Use these patterns throughout the report.

### Single-Method Result
"Method A achieved [metric] = [value] ([aggregation] across [N] seeds, [dispersion measure])."
Example: "SVM-RBF achieved F1 = 0.847 (median across 5 seeds, IQR [0.839, 0.855])."

### Comparison Between Methods
"Method A ([metric] = [value], [dispersion]) [outperformed/matched/underperformed] Method B ([value], [dispersion]) by [delta] ([relative] improvement)."
Example: "Adam (F1 = 0.921, IQR [0.918, 0.924]) outperformed SGD (0.800, [0.792, 0.808]) by +0.121 (+15.1% relative)."

### Statistical Test
"The difference was [significant/not significant] (p = [value], [test name], N = [sample size])."
Example: "The difference was significant (p < 0.01, Mann-Whitney U, N = 5 seeds per condition)."

### Hypothesis Resolution
"H-[X] predicted [prediction]. The result ([evidence]) [supports/partially supports/refutes] this hypothesis: [1-sentence explanation]."
Example: "H-1 predicted PCA would improve K-Means silhouette on Adult. The result (silhouette +0.005, p < 0.05) supports this hypothesis: PCA removed collinear features that degraded centroid estimation."

### Negative Result
"Contrary to H-[X], [what was expected] did not hold: [what actually happened]. This suggests [insight]."
Example: "Contrary to H-3, DR did not accelerate NN convergence: ICA reduced training time by 23% but PCA increased it by 8%. This suggests the acceleration depends on whether DR preserves the gradient landscape, not just dimensionality."

### Multi-Seed Default

Unless explicitly permitted otherwise:
- Run all core experiments with **≥5 seeds** (recommended: 42, 123, 456, 789, 1024)
- Report **median ± IQR** (preferred) or **mean ± std** for every quantitative claim
- Use seed=42 as the primary illustrative seed for learning curves and figures
- Statistical comparison: **Mann-Whitney U** (small N, non-parametric) or **Wilcoxon signed-rank** (paired)
- Single-seed results acceptable ONLY for: learning curve shape (not value), model-complexity curve shape, qualitative demonstrations
- **All tables must indicate aggregation method**: "median across 5 seeds" in caption or footnote

---

## Cross-Method Comparison Requirement

Every report must include comparative analysis across all methods. At minimum:

1. **Consolidated results table** — all methods × key metrics in one table. Readers should be able to compare any two methods without flipping pages.
2. **Trade-off visualization** — at least one figure showing performance vs. compute, accuracy vs. complexity, or similar trade-off dimensions.
3. **Decision guidance** — prose in Discussion or Conclusion answering: "When should a practitioner use Method A vs B?" Include context-dependent recommendations.
4. **Pareto frontier** (when applicable) — identify which methods are dominated (worse on ALL dimensions) vs. Pareto-optimal.
5. **Baseline anchoring** — every method compared against at least one common baseline (dummy, shuffled, or prior work).

---

## Negative Results Framing Guide

> **LL-77:** Negative results deserve more analytical space than positive ones. A refuted hypothesis generates more insight than a confirmed one.

### Allocation Rule
- Confirmed hypotheses: 1-2 paragraphs in Results + 1 paragraph in Discussion
- Refuted hypotheses: 1-2 paragraphs in Results + 2-3 paragraphs in Discussion (1.5x allocation)
- The Discussion section should LEAD with the most unexpected finding

### Framing Pattern
1. State the expectation clearly: "We hypothesized that X would Y"
2. State the result clearly: "Instead, we observed Z"
3. Explain WHY the expectation was wrong: "This occurred because..."
4. State what this teaches: "This reveals that..."
5. State the implication: "For practitioners, this means..."

### Title Integration
If the most important finding is negative, it should be in the title:
- BAD: "A Study of Regularization Techniques for MLPs"
- GOOD: "Regularization Uniformly Degrades Performance in Capacity-Matched MLPs"
- BEST: "Optimizer Choice Alone Drives Generalization: Regularization Adds No Value on Tabular Data"

---

## Title Construction Templates

> **LL-76:** Title quality is the highest-leverage writing improvement. A claim-based title communicates the contribution; a descriptive title just says what was done.

### Progression (worst → best)
1. **Descriptive:** "A Study of X on Y" — says what was done, not what was found
2. **Finding:** "X Outperforms Y on Z" — states the result
3. **Claim + boundary:** "X Outperforms Y in High-Dimensional but Not Low-Dimensional Spaces" — states result with applicability boundary
4. **Claim + mechanism + insight:** "X Achieves Y Where Z Cannot: W Is the Bottleneck, Not V" — states result, contrast, and the key insight

### Templates
- "[Method] [achieves/outperforms] [result] on [dataset/domain]: [key insight]"
- "[Finding]: [Mechanism] [matters/drives/determines] [outcome]"
- "[Negative claim]: [Expected approach] [fails/adds no value] [because insight]"
- "[Boundary claim]: [Method] [works] in [context A] but Not [context B]"

### Self-Test
Ask: "Could someone reading ONLY the title decide whether this paper is relevant to their work?" If no, the title is too descriptive.
