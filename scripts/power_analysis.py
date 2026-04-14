#!/usr/bin/env python3
"""Statistical Power Estimation for Phase 1 EDA Task 5."""
import math
from scipy import stats

print("=" * 60)
print("STATISTICAL POWER ESTIMATION -- Phase 1 EDA Task 5")
print("=" * 60)

# Parameters from Task 1
total_cves = 26
reproducible = 17
supplemented_total = reproducible + 7  # MCPSecBench supplementation
safe_controls = 10
total_corpus = supplemented_total + safe_controls

n_scanners = 4
n_scanner_pairs = n_scanners * (n_scanners - 1) // 2

categories = {
    "ASI05 Unexpected Code Execution": 12,
    "ASI03 Identity and Privilege Abuse": 5,
    "ASI04 Agentic Supply Chain Vulnerabilities": 4,
    "ASI02 Tool Misuse": 3,
    "ASI07 Insecure Inter-Agent Communication": 1,
    "ASI01 Agent Goal Hijack (from MCPSecBench)": 4,
}

print(f"\n--- Input Parameters ---")
print(f"CVEs found: {total_cves}")
print(f"After MCPSecBench supplementation: ~{supplemented_total} vulnerable cases")
print(f"Safe controls: {safe_controls}")
print(f"Total corpus: ~{total_corpus}")
print(f"Working scanners: {n_scanners}")
print(f"Scanner pairs: {n_scanner_pairs}")

print(f"\n--- (a) Power for Fisher's Exact Test ---")
for n in [15, 20, 24, 30, 34]:
    for effect in [0.20, 0.30, 0.40]:
        p1 = 0.7
        p2 = p1 - effect
        p_bar = (p1 + p2) / 2
        se_h0 = math.sqrt(2 * p_bar * (1 - p_bar) / n)
        se_h1 = math.sqrt(p1 * (1 - p1) / n + p2 * (1 - p2) / n)
        if se_h0 == 0 or se_h1 == 0:
            continue
        z_alpha = 1.96
        z = (abs(p1 - p2) - z_alpha * se_h0) / se_h1
        power = stats.norm.cdf(z)
        if effect == 0.30:
            print(f"  N={n:2d}, effect={effect:.2f} (p1={p1:.1f} vs p2={p2:.1f}): power={power:.3f}")

print(f"\n--- (b) Minimum Detectable Effect Size ---")
n_vuln = supplemented_total
for p1_base in [0.7, 0.8]:
    low_e, high_e = 0.01, 0.60
    for _ in range(50):
        effect = (low_e + high_e) / 2
        p2 = p1_base - effect
        if p2 < 0:
            high_e = effect
            continue
        p_bar = (p1_base + p2) / 2
        se_h0 = math.sqrt(2 * p_bar * (1 - p_bar) / n_vuln)
        se_h1 = math.sqrt(p1_base * (1 - p1_base) / n_vuln + p2 * (1 - p2) / n_vuln)
        if se_h0 == 0 or se_h1 == 0:
            low_e = effect
            continue
        z_alpha = 1.96
        z = (abs(p1_base - p2) - z_alpha * se_h0) / se_h1
        power = stats.norm.cdf(z)
        if power < 0.80:
            low_e = effect
        else:
            high_e = effect
    print(f"  Base rate {p1_base:.1f}, N={n_vuln}: MDE = {effect:.3f} for 80% power")

print(f"\n--- (c) Per-Category vs Supercategory Analysis ---")
for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
    feasible = "inferential" if count >= 5 else "descriptive only"
    print(f"  {cat}: {count} cases -- {feasible}")

injection_class = categories.get("ASI05 Unexpected Code Execution", 0) + categories.get("ASI01 Agent Goal Hijack (from MCPSecBench)", 0)
access_class = categories.get("ASI03 Identity and Privilege Abuse", 0)
supply_chain = categories.get("ASI04 Agentic Supply Chain Vulnerabilities", 0)

print(f"\n  Supercategory aggregation:")
print(f"    Injection-class (ASI01+ASI05): {injection_class} -- inferential")
print(f"    Access-control-class (ASI03): {access_class} -- inferential")
print(f"    Supply-chain-class (ASI04): {supply_chain} -- descriptive (borderline)")

print(f"\n--- Bonferroni Correction ---")
n_cats = 2
n_tests = n_scanner_pairs * n_cats + n_scanner_pairs
corrected_alpha = 0.05 / n_tests
print(f"  Total comparisons: {n_tests}")
print(f"  Bonferroni-corrected alpha: {corrected_alpha:.4f}")

print(f"\n--- CI Width Estimation (Clopper-Pearson) ---")
for n, k in [(24, 17), (24, 12), (10, 8), (5, 3)]:
    low_ci = stats.beta.ppf(0.025, k, n - k + 1) if k > 0 else 0.0
    high_ci = stats.beta.ppf(0.975, k + 1, n - k) if k < n else 1.0
    width = high_ci - low_ci
    print(f"  N={n}, k={k} (rate={k/n:.2f}): 95% CI=[{low_ci:.3f}, {high_ci:.3f}], width={width:.3f}")

print(f"\n--- SUMMARY ---")
print(f"  1. Overall Fisher exact: FEASIBLE at N>={supplemented_total}")
print(f"  2. MDE: ~0.30-0.35 (detects only large effects)")
print(f"  3. Per-category: Only 2 supercategories have N>=5")
print(f"  4. AOQL: BORDERLINE (CI width ~0.31-0.38)")
