#!/bin/bash
# Full Cisco evaluation across all 37 corpus cases
# Operating points:
# OP1: --analyzers yara --severity-filter all (static mode)
# OP2: --analyzers yara --severity-filter all (stdio mode, reads full docstrings)
# OP3: --analyzers yara --severity-filter high (static mode)
source ~/scanners/cisco_env/bin/activate

RESULTS_DIR=~/cisco_results
mkdir -p $RESULTS_DIR

# All test cases
VULN_CASES=$(ls ~/corpus/vulnerable/)
SAFE_CASES=$(ls ~/corpus/safe/)

echo "=== CISCO FULL EVALUATION ==="
echo "Start time: $(date)"

# OP1: Static mode, severity all
for case in $VULN_CASES; do
    mkdir -p $RESULTS_DIR/$case
    mcp-scanner --analyzers yara --source-path ~/corpus/vulnerable/$case/server.py --format raw --severity-filter all static --tools ~/corpus/vulnerable/$case/tools.json > $RESULTS_DIR/$case/op1_run1.json 2>/dev/null
    echo "OP1 vuln $case: done"
done

for case in $SAFE_CASES; do
    mkdir -p $RESULTS_DIR/$case
    mcp-scanner --analyzers yara --source-path ~/corpus/safe/$case/server.py --format raw --severity-filter all static --tools ~/corpus/safe/$case/tools.json > $RESULTS_DIR/$case/op1_run1.json 2>/dev/null
    echo "OP1 safe $case: done"
done

# OP2: Stdio mode, severity all (reads actual MCP descriptions)
for case in $VULN_CASES; do
    mcp-scanner --format raw --severity-filter all --analyzers yara stdio --stdio-command ~/scanners/corpus_env/bin/python3 --stdio-arg ~/corpus/vulnerable/$case/server.py > $RESULTS_DIR/$case/op2_run1.json 2>/dev/null
    echo "OP2 vuln $case: done"
done

for case in $SAFE_CASES; do
    mcp-scanner --format raw --severity-filter all --analyzers yara stdio --stdio-command ~/scanners/corpus_env/bin/python3 --stdio-arg ~/corpus/safe/$case/server.py > $RESULTS_DIR/$case/op2_run1.json 2>/dev/null
    echo "OP2 safe $case: done"
done

# OP3: Static mode, severity high only
for case in $VULN_CASES; do
    mcp-scanner --analyzers yara --source-path ~/corpus/vulnerable/$case/server.py --format raw --severity-filter high static --tools ~/corpus/vulnerable/$case/tools.json > $RESULTS_DIR/$case/op3_run1.json 2>/dev/null
    echo "OP3 vuln $case: done"
done

for case in $SAFE_CASES; do
    mcp-scanner --analyzers yara --source-path ~/corpus/safe/$case/server.py --format raw --severity-filter high static --tools ~/corpus/safe/$case/tools.json > $RESULTS_DIR/$case/op3_run1.json 2>/dev/null
    echo "OP3 safe $case: done"
done

echo "End time: $(date)"
echo "=== CISCO COMPLETE ==="
