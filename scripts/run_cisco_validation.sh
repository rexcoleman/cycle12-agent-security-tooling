#!/bin/bash
source ~/scanners/cisco_env/bin/activate

VULN_CASES="mcpsecbench_tool_poisoning cve_2025_68143 cve_2026_23744 cve_2025_6514 cve_2025_53107"
SAFE_CASE="safe_command_sanitized"

for case in $VULN_CASES; do
    echo "=== CISCO VULN: $case ==="
    OUTPUT=$(mcp-scanner --analyzers yara,behavioral --source-path ~/corpus/vulnerable/$case/server.py --format raw --severity-filter all static --tools ~/corpus/vulnerable/$case/tools.json 2>/dev/null)
    echo "$OUTPUT" | python3.12 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    results=d.get('scan_results',[])
    unsafe=[r for r in results if not r.get('is_safe',True)]
    findings=[]
    for r in results:
        for ak,av in r.get('findings',{}).items():
            if av.get('severity','SAFE') != 'SAFE':
                findings.append(ak+':'+av.get('severity','?')+':'+','.join(av.get('threat_names',[])))
    print('UNSAFE_TOOLS: '+str(len(unsafe))+'/'+str(len(results)))
    print('FINDINGS: '+str(findings))
except Exception as e:
    print('ERROR: '+str(e))
"
    echo "---"
done

echo "=== CISCO SAFE: $SAFE_CASE ==="
OUTPUT=$(mcp-scanner --analyzers yara,behavioral --source-path ~/corpus/safe/$SAFE_CASE/server.py --format raw --severity-filter all static --tools ~/corpus/safe/$SAFE_CASE/tools.json 2>/dev/null)
echo "$OUTPUT" | python3.12 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    results=d.get('scan_results',[])
    unsafe=[r for r in results if not r.get('is_safe',True)]
    print('UNSAFE_TOOLS: '+str(len(unsafe))+'/'+str(len(results)))
    if len(unsafe)==0:
        print('CLEAN: all safe')
    else:
        for r in results:
            for ak,av in r.get('findings',{}).items():
                if av.get('severity','SAFE') != 'SAFE':
                    print('FP: '+ak+':'+av.get('severity','?'))
except Exception as e:
    print('ERROR: '+str(e))
"
echo "---"
