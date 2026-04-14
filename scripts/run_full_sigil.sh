#!/bin/bash
# Full Sigil evaluation across all 37 corpus cases
export PATH="/opt/homebrew/bin:$PATH"

RESULTS_DIR=~/sigil_results
mkdir -p $RESULTS_DIR

VULN_CASES=$(ls ~/corpus/vulnerable/)
SAFE_CASES=$(ls ~/corpus/safe/)

echo "=== SIGIL FULL EVALUATION ==="
echo "Start time: $(date)"

for case in $VULN_CASES; do
    mkdir -p $RESULTS_DIR/$case
    sigil scan ~/corpus/vulnerable/$case/ > $RESULTS_DIR/$case/run1.txt 2>&1
    SCORE=$(cat $RESULTS_DIR/$case/run1.txt | grep "Risk Score:" | sed 's/.*Risk Score: //' | tr -dc '0-9' | head -c 2)
    echo "SIGIL vuln $case: score=$SCORE"
done

for case in $SAFE_CASES; do
    mkdir -p $RESULTS_DIR/$case
    sigil scan ~/corpus/safe/$case/ > $RESULTS_DIR/$case/run1.txt 2>&1
    SCORE=$(cat $RESULTS_DIR/$case/run1.txt | grep "Risk Score:" | sed 's/.*Risk Score: //' | tr -dc '0-9' | head -c 2)
    echo "SIGIL safe $case: score=$SCORE"
done

echo "End time: $(date)"
echo "=== SIGIL COMPLETE ==="
