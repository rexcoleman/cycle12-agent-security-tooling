# T3 Ensemble Scores

> **Scored:** 2026-04-16T07:18:19Z
> **Protocol:** T3 ensemble (5 Sonnet + Opus meta-review)

## Final Composite: 7.30

## Per-Dimension Scores

| Dimension | Pass Scores | Median | Spread | Confidence | Final |
|-----------|-------------|--------|--------|------------|-------|
| problem_selection | [8, 7, 8, 8, 7] | 8 | 1 | HIGH | **8** |
| novelty | [7, 7, 7, 7, 7] | 7 | 0 | HIGH | **7** |
| boundary_spanning | [6, 7, 6, 7, 6] | 6 | 1 | HIGH | **6** |
| rigor | [8, 8, 8, 8, 8] | 8 | 0 | HIGH | **8** |
| generalizability | [7, 7, 7, 7, 7] | 7 | 0 | HIGH | **7** |
| clarity | [8, 8, 8, 7, 8] | 8 | 1 | HIGH | **8** |
| surprise (diag.) | [7, 7, 7, 7, 7] | 7 | 0 | HIGH | **7** |
| fertility (diag.) | [7, 7, 7, 7, 7] | 7 | 0 | HIGH | **7** |

## Ensemble Diagnostics

- **Agreement:** Exceptional convergence across all 5 passes. All 8 dimensions (6 governable + 2 emergent) show spread ≤ 1.0, with 5 of 8 dimensions showing perfect agreement (spread = 0). The composite spread is only 0.4 points (range 7.0–7.4). All passes tell fundamentally the same story: this is a well-executed, rigorous empirical benchmarking study that applies established methodology to a genuinely understudied domain, producing actionable findings with honest scope limitations. The primary tension across passes is whether the manufacturing QA boundary-spanning constitutes genuine cross-domain synthesis (passes 2 and 4 score it 7) or cosmetic vocabulary reframing (passes 1, 3, and 5 score it 6), and whether the narrow scope justifies problem_selection at 8 (passes 1, 3, 4) or 7 (passes 2, 5). These are minor calibration differences, not fundamentally different readings.
- **Strongest consensus:** Rigor (all 5 passes: 8, spread = 0), Novelty (all 5 passes: 7, spread = 0), Generalizability (all 5 passes: 7, spread = 0), Surprise (all 5 passes: 7, spread = 0), and Fertility (all 5 passes: 7, spread = 0) — five dimensions with perfect unanimity. Rigor consensus is most diagnostic: every pass independently identified the same strengths (100% claim tagging, Bonferroni-corrected Fisher's exact, hostile baseline check, explicit counter-evidence reporting) and the same weaknesses (per-category N=3 without CIs, K-S test on 2-4 points, unverifiable pre-registration). This tells us the artifact's rigor infrastructure is unambiguously strong and its specific methodological gaps are equally unambiguous — the artifact is transparently self-documenting on both strengths and limitations.
- **Weakest consensus:** Boundary-spanning (spread = 1, scores 6-7) showed the most relative disagreement, though still within HIGH confidence. Passes 2 and 4 scored 7 (emphasizing the executed transfer test with measurable AOQL outcomes and practitioner-actionable vocabulary), while passes 1, 3, and 5 scored 6 (emphasizing that OC curves are mathematically equivalent to ROC curves and that the manufacturing QA connection is primarily vocabulary import without genuinely novel insight). This tells us boundary-spanning is the most subjective dimension for this artifact type — the question of whether a vocabulary reframe that improves practitioner communication constitutes 'genuine' cross-domain synthesis vs. 'cosmetic' relabeling involves a judgment call about what counts as insight. The median of 6 appropriately reflects the majority view that the transfer, while honestly executed and partially successful, does not produce analytical capability unavailable from standard ML/security evaluation methodology.
- **Outlier passes:** No pass diverged systematically. Pass 4 was marginally highest (composite 7.4) due to scoring boundary-spanning at 7, while Pass 5 was marginally lowest (composite 7.0) due to scoring both problem_selection and clarity lower by 1 point. Pass 5's lower problem_selection score (7) was justified by the argument that gap analysis relying on vendor blog posts as the prior state constitutes a weak baseline — a reasonable concern but one that the majority of passes found outweighed by the structural reframing of scanner evaluation methodology. No pass showed a systematic bias pattern of consistently scoring high or low across dimensions.

## Pass Composites

- Pass 1: 7.30
- Pass 2: 7.20
- Pass 3: 7.30
- Pass 4: 7.40
- Pass 5: 7.00
- **Spread:** 0.40
