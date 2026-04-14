#!/usr/bin/env python3
"""Test AgentSeal connectivity on 5 corpus servers."""
import subprocess
import os

CORPUS_BASE = "/Users/rexcolemanmacmini/corpus_staging"
PYTHON = "/Users/rexcolemanmacmini/scanners/corpus_env/bin/python3"

test_cases = [
    "vulnerable/cve_2026_0755",
    "vulnerable/cve_2026_0756",
    "vulnerable/mcpsecbench_tool_poisoning",
    "safe/safe_eval_literal",
    "safe/decoy_data_processor",
]

connected = 0
failed = 0
for case in test_cases:
    server = os.path.join(CORPUS_BASE, case, "server.py")
    cmd = f"source ~/scanners/agentseal_env/bin/activate && agentseal scan-mcp --command '{PYTHON} {server}' 2>&1"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    output = result.stdout + result.stderr
    if "connected" in output and "0 failed" in output:
        connected += 1
        status = "CONNECTED"
    else:
        failed += 1
        status = "FAILED"
    print(f"  {status}: {case}")

print(f"\nAgentSeal: {connected} connected, {failed} failed out of {len(test_cases)} tested")
