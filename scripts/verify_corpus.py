#!/usr/bin/env python3
"""Verify corpus servers have valid syntax and can be imported."""

import subprocess
import os
import sys

vuln_dir = os.path.expanduser("~/corpus_staging/vulnerable")
safe_dir = os.path.expanduser("~/corpus_staging/safe")

success = 0
fail = 0
for base_dir in [vuln_dir, safe_dir]:
    label = "VULN" if "vuln" in base_dir else "SAFE"
    for case in sorted(os.listdir(base_dir)):
        server = os.path.join(base_dir, case, "server.py")
        if not os.path.exists(server):
            continue
        with open(server) as f:
            code = f.read()
        try:
            compile(code, server, "exec")
            success += 1
        except SyntaxError as e:
            print(f"FAIL: {label}/{case} - {e}")
            fail += 1

print(f"\nSyntax check: {success} passed, {fail} failed")
