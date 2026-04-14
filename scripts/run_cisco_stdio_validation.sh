#!/bin/bash
source ~/scanners/cisco_env/bin/activate

VULN_CASES="mcpsecbench_tool_poisoning cve_2025_68143 cve_2026_23744 cve_2025_6514 cve_2025_53107"
SAFE_CASE="safe_command_sanitized"

for case in $VULN_CASES; do
    echo "=== CISCO STDIO VULN: $case ==="
    mcp-scanner --format raw --severity-filter all --analyzers yara stdio --stdio-command ~/scanners/corpus_env/bin/python3 --stdio-arg ~/corpus/vulnerable/$case/server.py 2>/dev/null | /opt/homebrew/bin/python3.12 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    r=d.get('scan_results',[])
    unsafe=[x for x in r if not x.get('is_safe',True)]
    print('DETECT: '+str(len(unsafe))+'/'+str(len(r))+' tools flagged')
    for u in unsafe:
        f=u.get('findings',{})
        for ak,av in f.items():
            if av.get('severity','SAFE')!='SAFE':
                print('  '+ak+': '+av.get('severity','')+' - '+','.join(av.get('threat_names',[])))
except Exception as e:
    print('ERROR: '+str(e))
"
    echo "---"
done

echo "=== CISCO STDIO SAFE: $SAFE_CASE ==="
mcp-scanner --format raw --severity-filter all --analyzers yara stdio --stdio-command ~/scanners/corpus_env/bin/python3 --stdio-arg ~/corpus/safe/$SAFE_CASE/server.py 2>/dev/null | /opt/homebrew/bin/python3.12 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    r=d.get('scan_results',[])
    unsafe=[x for x in r if not x.get('is_safe',True)]
    print('DETECT: '+str(len(unsafe))+'/'+str(len(r))+' tools flagged')
    if len(unsafe)==0:
        print('CLEAN')
except Exception as e:
    print('ERROR: '+str(e))
"
echo "---"
