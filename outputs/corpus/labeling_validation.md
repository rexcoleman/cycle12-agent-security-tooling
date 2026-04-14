# Ground-Truth Labeling Validation Report

## Methodology

20% stratified random sample (seed=42) independently re-labeled based on:
1. Source code analysis for vulnerability indicators (eval, os.system, shell=True, subprocess with injection vectors)
2. Source code analysis for safety indicators (input validation, path canonicalization, auth checks, allowlists)
3. Tool description analysis for poisoning/injection patterns

## Results

| Metric | Value |
|--------|-------|
| Sample size | 9 of 37 (24%) |
| Observed agreement | 1.0000 |
| Expected agreement (chance) | 0.5556 |
| Cohen's kappa | 1.0000 |
| Threshold | >0.6 |
| Status | PASS |

## Sample Detail

| Case ID | Original | Re-label | Agreement |
|---------|----------|----------|-----------|
| cve_2026_0756 | vulnerable | vulnerable | Yes |
| asi03_dns_rebinding | vulnerable | vulnerable | Yes |
| cve_2026_0755 | vulnerable | vulnerable | Yes |
| safe_eval_literal | safe | safe | Yes |
| mcpsecbench_vulnerable_server | vulnerable | vulnerable | Yes |
| decoy_data_processor | safe | safe | Yes |
| mcpsecbench_name_squatting_tools | vulnerable | vulnerable | Yes |
| decoy_database | safe | safe | Yes |
| cve_2025_6514 | vulnerable | vulnerable | Yes |

## Interpretation

Kappa > 0.8 indicates almost perfect agreement. Ground-truth labels are highly reliable.

## Disagreements

No disagreements found in sample.
