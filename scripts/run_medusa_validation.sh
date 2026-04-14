#!/bin/bash
source ~/scanners/medusa_env/bin/activate

VULN_CASES="mcpsecbench_tool_poisoning cve_2025_68143 cve_2026_23744 cve_2025_6514 cve_2025_53107"
SAFE_CASE="safe_command_sanitized"

for case in $VULN_CASES; do
    echo "=== MEDUSA VULN: $case ==="
    OUTPUT=$(medusa scan ~/corpus/vulnerable/$case/ --format json 2>/dev/null)
    echo "$OUTPUT" | python3.12 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    findings=d if isinstance(d,list) else d.get('findings',[]) if isinstance(d,dict) else []
    # Filter to relevant scanners
    relevant=['MCPServerScanner','OWASPLLMScanner','ToolCallbackScanner']
    filtered=[f for f in findings if f.get('scanner','') in relevant or f.get('source','') in relevant]
    total=len(findings)
    high=[f for f in filtered if f.get('severity','').upper() in ['HIGH','CRITICAL']]
    med=[f for f in filtered if f.get('severity','').upper()=='MEDIUM']
    print('TOTAL_FINDINGS: '+str(total)+' FILTERED: '+str(len(filtered))+' HIGH: '+str(len(high))+' MED: '+str(len(med)))
    for f in filtered[:5]:
        print('  '+f.get('scanner',f.get('source','?'))+': '+f.get('severity','?')+' - '+str(f.get('title',f.get('message',''))[:80]))
except Exception as e:
    print('PARSE_ERROR: '+str(e))
    # Try to print raw for debugging
    sys.stdin.seek(0)
    print(sys.stdin.read()[:500])
" 2>&1
    echo "---"
done

echo "=== MEDUSA SAFE: $SAFE_CASE ==="
OUTPUT=$(medusa scan ~/corpus/safe/$SAFE_CASE/ --format json 2>/dev/null)
echo "$OUTPUT" | python3.12 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    findings=d if isinstance(d,list) else d.get('findings',[]) if isinstance(d,dict) else []
    relevant=['MCPServerScanner','OWASPLLMScanner','ToolCallbackScanner']
    filtered=[f for f in findings if f.get('scanner','') in relevant or f.get('source','') in relevant]
    high=[f for f in filtered if f.get('severity','').upper() in ['HIGH','CRITICAL']]
    print('TOTAL_FINDINGS: '+str(len(findings))+' FILTERED: '+str(len(filtered))+' HIGH: '+str(len(high)))
    if len(filtered)==0:
        print('CLEAN: no relevant findings')
    else:
        for f in filtered[:5]:
            print('  FP: '+f.get('scanner',f.get('source','?'))+': '+f.get('severity','?')+' - '+str(f.get('title',f.get('message',''))[:80]))
except Exception as e:
    print('PARSE_ERROR: '+str(e))
" 2>&1
echo "---"
