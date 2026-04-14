#!/bin/bash
# Full MEDUSA evaluation across all 37 corpus cases
source ~/scanners/medusa_env/bin/activate

RESULTS_DIR=~/medusa_results
mkdir -p $RESULTS_DIR

VULN_CASES=$(ls ~/corpus/vulnerable/)
SAFE_CASES=$(ls ~/corpus/safe/)

echo "=== MEDUSA FULL EVALUATION ==="
echo "Start time: $(date)"

for case in $VULN_CASES; do
    mkdir -p $RESULTS_DIR/$case
    echo "MEDUSA vuln $case: scanning..."
    echo "yes" | medusa scan ~/corpus/vulnerable/$case/ --format json 2>/dev/null > /dev/null
    # Get the latest report
    REPORT=$(ls -t ~/.medusa/reports/medusa-scan-*.json 2>/dev/null | head -1)
    if [ -n "$REPORT" ]; then
        cp "$REPORT" $RESULTS_DIR/$case/run1.json
        echo "MEDUSA vuln $case: done"
    else
        echo "MEDUSA vuln $case: NO REPORT"
    fi
done

for case in $SAFE_CASES; do
    mkdir -p $RESULTS_DIR/$case
    echo "MEDUSA safe $case: scanning..."
    echo "yes" | medusa scan ~/corpus/safe/$case/ --format json 2>/dev/null > /dev/null
    REPORT=$(ls -t ~/.medusa/reports/medusa-scan-*.json 2>/dev/null | head -1)
    if [ -n "$REPORT" ]; then
        cp "$REPORT" $RESULTS_DIR/$case/run1.json
        echo "MEDUSA safe $case: done"
    else
        echo "MEDUSA safe $case: NO REPORT"
    fi
done

echo "End time: $(date)"
echo "=== MEDUSA COMPLETE ==="
