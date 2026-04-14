#!/usr/bin/env python3
"""Parse MEDUSA JSON output and summarize findings."""
import sys
import json

data = json.load(sys.stdin)
print(f"Total findings: {len(data)}")
severities = {}
scanners = {}
for f in data:
    sev = f.get("severity", "UNKNOWN")
    scanner = f.get("scanner", "UNKNOWN")
    severities[sev] = severities.get(sev, 0) + 1
    scanners[scanner] = scanners.get(scanner, 0) + 1

print(f"By severity: {severities}")
print(f"By scanner: {scanners}")
print("\nTop findings:")
for f in data[:10]:
    issue = f.get("issue", "?")[:80]
    sev = f.get("severity", "?")
    scanner = f.get("scanner", "?")
    line = f.get("line", "?")
    print(f"  [{sev}] {scanner} L{line}: {issue}")
