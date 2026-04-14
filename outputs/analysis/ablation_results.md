# Ablation Results

## Ablation 1: Binary aggregation
Already computed as 'ALL' category in detection profiles.

## Ablation 2: Exclude safe cases
  cisco OP1_static_all: TPR=0.08
  cisco OP2_stdio_all: TPR=0.08
  cisco OP3_static_high: TPR=0.08
  medusa OP1_any: TPR=0.96
  medusa OP2_medium: TPR=0.96
  medusa OP3_high: TPR=0.16
  medusa OP4_critical: TPR=0.16
  sigil OP1_score_gt13: TPR=0.8
  sigil OP2_score_gt19: TPR=0.36

## Ablation 3: Remove LLM-judge scanners
Not applicable — no scanners used LLM analysis (no API keys configured).
All scanner results are from rule-based/pattern-matching analysis only.

## Ablation 4: Strict vs lenient labeling
Strict: Only CWE-78 (command injection) and CWE-94 (code injection) count as vulnerable.
  cisco OP1_static_all: TPR=0.0909 FPR=0.0385 Youden=0.0524
  cisco OP2_stdio_all: TPR=0.0909 FPR=0.0385 Youden=0.0524
  cisco OP3_static_high: TPR=0.0909 FPR=0.0385 Youden=0.0524
  medusa OP1_any: TPR=1.0 FPR=0.9615 Youden=0.0385
  medusa OP2_medium: TPR=1.0 FPR=0.9615 Youden=0.0385
  medusa OP3_high: TPR=0.2727 FPR=0.0385 Youden=0.2343
  medusa OP4_critical: TPR=0.2727 FPR=0.0385 Youden=0.2343
  sigil OP1_score_gt13: TPR=1.0 FPR=0.5769 Youden=0.4231
  sigil OP2_score_gt19: TPR=0.5455 FPR=0.2308 Youden=0.3147

## Ablation 5: Clustered bootstrap (H-3)
Server-level clustering: each server is a cluster.
Since each test case is an independent server (1 case per server),
server-level clustering = standard bootstrap. No clustering effect expected.
H-3 resolution: SUPPORTED — independence assumption holds because
each test case IS an independent server, not multiple vulns in one server.
