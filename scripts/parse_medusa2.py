#!/usr/bin/env python3
"""Parse MEDUSA JSON report (dict format)."""
import sys
import json

data = json.load(open(sys.argv[1]))
print("Summary:", json.dumps(data["scan_summary"], indent=2))
print("Severity:", json.dumps(data["severity_breakdown"], indent=2))
findings = data["findings"]
print(f"Findings: {len(findings)}")
for f in findings:
    sev = f.get("severity", "?")
    scanner = f.get("scanner", "?")
    line = f.get("line", "?")
    issue = str(f.get("issue", "?"))[:80]
    print(f"  [{sev}] {scanner} L{line}: {issue}")
