#!/bin/bash
export PATH="/opt/homebrew/bin:$PATH"

VULN_CASES="mcpsecbench_tool_poisoning cve_2025_68143 cve_2026_23744 cve_2025_6514 cve_2025_53107"
SAFE_CASES="safe_command_sanitized safe_eval_literal decoy_database"

for case in $VULN_CASES; do
    echo "=== SIGIL VULN: $case ==="
    OUTPUT=$(sigil scan ~/corpus/vulnerable/$case/ 2>&1)
    SCORE=$(echo "$OUTPUT" | grep "Risk Score:" | sed 's/.*Risk Score: //' | tr -dc '0-9')
    VERDICT=$(echo "$OUTPUT" | grep "VERDICT:" | sed 's/.*VERDICT: //' | sed 's/[^A-Z ]//g' | head -1)
    BANDIT=$(echo "$OUTPUT" | grep "Bandit found" | head -1)
    echo "SCORE: $SCORE  VERDICT: $VERDICT  BANDIT: $BANDIT"
    echo "---"
done

for case in $SAFE_CASES; do
    echo "=== SIGIL SAFE: $case ==="
    OUTPUT=$(sigil scan ~/corpus/safe/$case/ 2>&1)
    SCORE=$(echo "$OUTPUT" | grep "Risk Score:" | sed 's/.*Risk Score: //' | tr -dc '0-9')
    VERDICT=$(echo "$OUTPUT" | grep "VERDICT:" | sed 's/.*VERDICT: //' | sed 's/[^A-Z ]//g' | head -1)
    BANDIT=$(echo "$OUTPUT" | grep "Bandit found" | head -1)
    echo "SCORE: $SCORE  VERDICT: $VERDICT  BANDIT: $BANDIT"
    echo "---"
done
