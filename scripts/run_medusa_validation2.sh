#!/bin/bash
source ~/scanners/medusa_env/bin/activate

VULN_CASES="mcpsecbench_tool_poisoning cve_2025_68143 cve_2026_23744 cve_2025_6514 cve_2025_53107"
SAFE_CASE="safe_command_sanitized"

# Clean old reports
rm -f ~/.medusa/reports/medusa-scan-validation-*.json

for case in $VULN_CASES; do
    echo "=== MEDUSA VULN: $case ==="
    echo "yes" | medusa scan ~/corpus/vulnerable/$case/ --format json 2>/dev/null > /dev/null
    # Get the latest report
    REPORT=$(ls -t ~/.medusa/reports/medusa-scan-*.json 2>/dev/null | head -1)
    if [ -n "$REPORT" ]; then
        /opt/homebrew/bin/python3.12 -c "
import json
with open('$REPORT') as f:
    d=json.load(f)
findings=d.get('findings',[])
relevant=['MCPServerScanner','OWASPLLMScanner','ToolCallbackScanner']
rel_findings=[f for f in findings if f.get('scanner','') in relevant]
high=[f for f in rel_findings if f.get('severity','') in ['CRITICAL','HIGH']]
med=[f for f in rel_findings if f.get('severity','')=='MEDIUM']
print('RELEVANT: '+str(len(rel_findings))+' (CRIT/HIGH: '+str(len(high))+', MED: '+str(len(med))+')')
for f in rel_findings[:5]:
    print('  '+f.get('scanner','')+' | '+f.get('severity','')+' | '+str(f.get('issue',''))[:80])
"
        # Rename to avoid confusion
        cp "$REPORT" ~/.medusa/reports/validation_vuln_${case}.json
    else
        echo "NO REPORT GENERATED"
    fi
    echo "---"
done

echo "=== MEDUSA SAFE: $SAFE_CASE ==="
echo "yes" | medusa scan ~/corpus/safe/$SAFE_CASE/ --format json 2>/dev/null > /dev/null
REPORT=$(ls -t ~/.medusa/reports/medusa-scan-*.json 2>/dev/null | head -1)
if [ -n "$REPORT" ]; then
    /opt/homebrew/bin/python3.12 -c "
import json
with open('$REPORT') as f:
    d=json.load(f)
findings=d.get('findings',[])
relevant=['MCPServerScanner','OWASPLLMScanner','ToolCallbackScanner']
rel_findings=[f for f in findings if f.get('scanner','') in relevant]
high=[f for f in rel_findings if f.get('severity','') in ['CRITICAL','HIGH']]
print('RELEVANT: '+str(len(rel_findings))+' (CRIT/HIGH: '+str(len(high))+')')
for f in rel_findings[:5]:
    print('  '+f.get('scanner','')+' | '+f.get('severity','')+' | '+str(f.get('issue',''))[:80])
if len(rel_findings)==0:
    print('CLEAN: no relevant findings')
"
    cp "$REPORT" ~/.medusa/reports/validation_safe_${SAFE_CASE}.json
fi
echo "---"
