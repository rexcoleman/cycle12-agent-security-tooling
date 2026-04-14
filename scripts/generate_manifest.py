#!/usr/bin/env python3
"""Generate corpus manifest.csv from individual manifest.json files."""
import os
import json
import csv

CORPUS_DIR = os.path.expanduser("~/cycle12-agent-security-tooling/outputs/corpus")
OUTPUT_CSV = os.path.join(CORPUS_DIR, "manifest.csv")

rows = []
for label_dir in ["vulnerable", "safe"]:
    base = os.path.join(CORPUS_DIR, label_dir)
    for case_id in sorted(os.listdir(base)):
        manifest_path = os.path.join(base, case_id, "manifest.json")
        if not os.path.exists(manifest_path):
            continue
        with open(manifest_path) as f:
            m = json.load(f)
        rows.append({
            "test_case_id": m.get("id", case_id),
            "category": m.get("owasp_category", "N/A"),
            "ground_truth_label": m.get("ground_truth", label_dir),
            "source_cve": m.get("cve", "N/A"),
            "cwe": m.get("cwe", "N/A"),
            "cvss": str(m.get("cvss", "N/A")),
            "vulnerability_type": m.get("vulnerability_type", "none"),
            "confidence": "high",
            "notes": m.get("description", ""),
        })

with open(OUTPUT_CSV, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=[
        "test_case_id", "category", "ground_truth_label", "source_cve",
        "cwe", "cvss", "vulnerability_type", "confidence", "notes"
    ])
    writer.writeheader()
    writer.writerows(rows)

print(f"Manifest written: {len(rows)} entries to {OUTPUT_CSV}")

# Category summary
vuln_cats = {}
safe_count = 0
for r in rows:
    if r["ground_truth_label"] == "vulnerable":
        cat = r["category"]
        vuln_cats[cat] = vuln_cats.get(cat, 0) + 1
    else:
        safe_count += 1

print(f"\nVulnerable by category:")
for cat, count in sorted(vuln_cats.items()):
    print(f"  {cat}: {count}")
print(f"Safe: {safe_count}")
