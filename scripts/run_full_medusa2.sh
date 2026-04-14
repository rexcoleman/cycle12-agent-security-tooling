#!/bin/bash
# Full MEDUSA evaluation - uses 'yes' pipe to handle interactive prompts
source ~/scanners/medusa_env/bin/activate

RESULTS_DIR=~/medusa_results
mkdir -p $RESULTS_DIR

VULN_CASES=$(ls ~/corpus/vulnerable/)
SAFE_CASES=$(ls ~/corpus/safe/)

echo "=== MEDUSA FULL EVALUATION (v2) ==="
echo "Start time: $(date)"

# Skip already-completed cases
for case in $VULN_CASES; do
    if [ -f "$RESULTS_DIR/$case/run1.json" ]; then
        echo "MEDUSA vuln $case: SKIP (already done)"
        continue
    fi
    mkdir -p $RESULTS_DIR/$case
    echo "MEDUSA vuln $case: scanning..."
    # Use 'yes' command to auto-answer any interactive prompts
    yes | timeout 120 medusa scan ~/corpus/vulnerable/$case/ --format json 2>/dev/null > /dev/null
    REPORT=$(ls -t ~/.medusa/reports/medusa-scan-*.json 2>/dev/null | head -1)
    if [ -n "$REPORT" ]; then
        cp "$REPORT" $RESULTS_DIR/$case/run1.json
        echo "MEDUSA vuln $case: done"
    else
        echo "MEDUSA vuln $case: NO REPORT"
        # Create an empty result file
        echo '{"findings":[]}' > $RESULTS_DIR/$case/run1.json
    fi
done

for case in $SAFE_CASES; do
    if [ -f "$RESULTS_DIR/$case/run1.json" ]; then
        echo "MEDUSA safe $case: SKIP (already done)"
        continue
    fi
    mkdir -p $RESULTS_DIR/$case
    echo "MEDUSA safe $case: scanning..."
    yes | timeout 120 medusa scan ~/corpus/safe/$case/ --format json 2>/dev/null > /dev/null
    REPORT=$(ls -t ~/.medusa/reports/medusa-scan-*.json 2>/dev/null | head -1)
    if [ -n "$REPORT" ]; then
        cp "$REPORT" $RESULTS_DIR/$case/run1.json
        echo "MEDUSA safe $case: done"
    else
        echo "MEDUSA safe $case: NO REPORT"
        echo '{"findings":[]}' > $RESULTS_DIR/$case/run1.json
    fi
done

echo "End time: $(date)"
echo "Total results: $(ls $RESULTS_DIR | wc -l)"
echo "=== MEDUSA COMPLETE ==="
