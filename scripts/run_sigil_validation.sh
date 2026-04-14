#!/bin/bash
export PATH="/opt/homebrew/bin:$PATH"

VULN_CASES="mcpsecbench_tool_poisoning cve_2025_68143 cve_2026_23744 cve_2025_6514 cve_2025_53107"
SAFE_CASE="safe_command_sanitized"

for case in $VULN_CASES; do
    echo "=== SIGIL VULN: $case ==="
    sigil scan ~/corpus/vulnerable/$case/ 2>&1 | tail -20
    echo "---"
done

echo "=== SIGIL SAFE: $SAFE_CASE ==="
sigil scan ~/corpus/safe/$SAFE_CASE/ 2>&1 | tail -20
echo "---"
