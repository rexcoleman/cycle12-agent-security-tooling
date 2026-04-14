#!/bin/bash
export PATH="/opt/homebrew/bin:$PATH"

VULN_CASES="mcpsecbench_tool_poisoning cve_2025_68143 cve_2026_23744 cve_2025_6514 cve_2025_53107"
SAFE_CASE="safe_command_sanitized"

for case in $VULN_CASES; do
    echo "=== SIGIL VULN: $case ==="
    OUTPUT=$(sigil scan ~/corpus/vulnerable/$case/ 2>&1)
    SCORE=$(echo "$OUTPUT" | grep -oP 'Risk Score: \K[0-9]+')
    VERDICT=$(echo "$OUTPUT" | grep -oP 'VERDICT: \K[A-Z ]+' | head -1)
    BANDIT=$(echo "$OUTPUT" | grep -oP 'Bandit found \K[0-9]+ high/medium severity issues' || echo "no bandit findings")
    echo "SCORE: $SCORE  VERDICT: $VERDICT  BANDIT: $BANDIT"
    echo "---"
done

echo "=== SIGIL SAFE: $SAFE_CASE ==="
OUTPUT=$(sigil scan ~/corpus/safe/$SAFE_CASE/ 2>&1)
SCORE=$(echo "$OUTPUT" | grep -oP 'Risk Score: \K[0-9]+')
VERDICT=$(echo "$OUTPUT" | grep -oP 'VERDICT: \K[A-Z ]+' | head -1)
BANDIT=$(echo "$OUTPUT" | grep -oP 'Bandit found \K[0-9]+ high/medium severity issues' || echo "no bandit findings")
echo "SCORE: $SCORE  VERDICT: $VERDICT  BANDIT: $BANDIT"
echo "---"

# Also test additional safe cases
echo "=== SIGIL SAFE: safe_eval_literal ==="
OUTPUT=$(sigil scan ~/corpus/safe/safe_eval_literal/ 2>&1)
SCORE=$(echo "$OUTPUT" | grep -oP 'Risk Score: \K[0-9]+')
echo "SCORE: $SCORE"
echo "---"

echo "=== SIGIL SAFE: decoy_database ==="
OUTPUT=$(sigil scan ~/corpus/safe/decoy_database/ 2>&1)
SCORE=$(echo "$OUTPUT" | grep -oP 'Risk Score: \K[0-9]+')
echo "SCORE: $SCORE"
echo "---"
