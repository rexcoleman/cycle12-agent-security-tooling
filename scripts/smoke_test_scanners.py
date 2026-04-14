#!/usr/bin/env python3
"""Smoke test all 4 scanners on 3 corpus samples."""
import subprocess
import os
import json
import sys

VULN_DIR = os.path.expanduser("~/corpus_staging/vulnerable")
SAFE_DIR = os.path.expanduser("~/corpus_staging/safe")

# Test cases: 1 vulnerable, 1 safe, 1 decoy
TEST_CASES = [
    ("vulnerable", os.path.join(VULN_DIR, "cve_2026_0755")),
    ("safe", os.path.join(SAFE_DIR, "safe_eval_literal")),
    ("decoy", os.path.join(SAFE_DIR, "decoy_data_processor")),
]

def run_cmd(cmd, timeout=60, env=None):
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=timeout, env=env)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -2, "", str(e)

print("=" * 70)
print("SCANNER SMOKE TEST ON CORPUS SAMPLE")
print("=" * 70)

# 1. Cisco MCP Scanner
print("\n### CISCO MCP SCANNER ###")
for label, case_dir in TEST_CASES:
    tools_json = os.path.join(case_dir, "tools.json")
    cmd = f"source ~/scanners/cisco_env/bin/activate && mcp-scanner scan --format raw {tools_json}"
    rc, out, err = run_cmd(cmd, timeout=120)
    # Parse output
    try:
        data = json.loads(out) if out.strip() else {}
        findings_count = 0
        is_safe_all = True
        for server in data.get("servers", []):
            for tool in server.get("tools", []):
                if not tool.get("is_safe", True):
                    is_safe_all = False
                for analyzer, result in tool.get("findings", {}).items():
                    findings_count += result.get("total_findings", 0)
        verdict = "SAFE" if is_safe_all else f"UNSAFE ({findings_count} findings)"
    except (json.JSONDecodeError, KeyError, TypeError):
        verdict = f"PARSE_ERROR (rc={rc}, out={out[:200]}, err={err[:200]})"
    print(f"  {label}: {verdict}")

# 2. AgentSeal
print("\n### AGENTSEAL ###")
for label, case_dir in TEST_CASES:
    server_py = os.path.join(case_dir, "server.py")
    # AgentSeal needs to run the server - use corpus_env python for the server
    python_path = os.path.expanduser("~/scanners/corpus_env/bin/python3")
    cmd = f"source ~/scanners/agentseal_env/bin/activate && agentseal scan-mcp --command '{python_path} {server_py}' 2>&1"
    rc, out, err = run_cmd(cmd, timeout=60)
    combined = out + err
    if "trust_scores" in combined or "findings" in combined or "total_tools" in combined:
        try:
            data = json.loads(out) if out.strip().startswith("{") else {}
            if data:
                total_findings = data.get("summary", {}).get("total_findings", "?")
                verdict = f"CONNECTED ({total_findings} findings)"
            else:
                # Try to find key info in text output
                verdict = f"OUTPUT (rc={rc}): {combined[:200]}"
        except json.JSONDecodeError:
            verdict = f"OUTPUT (rc={rc}): {combined[:200]}"
    elif "error" in combined.lower() or "fail" in combined.lower():
        verdict = f"FAIL: {combined[:200]}"
    else:
        verdict = f"UNKNOWN (rc={rc}): {combined[:200]}"
    print(f"  {label}: {verdict}")

# 3. MEDUSA
print("\n### MEDUSA ###")
for label, case_dir in TEST_CASES:
    cmd = f"source ~/scanners/medusa_env/bin/activate && medusa scan {case_dir} --format json 2>/dev/null"
    rc, out, err = run_cmd(cmd, timeout=120)
    try:
        if out.strip().startswith("[") or out.strip().startswith("{"):
            data = json.loads(out)
            if isinstance(data, list):
                findings_count = len(data)
                severities = {}
                for f in data:
                    sev = f.get("severity", "UNKNOWN")
                    severities[sev] = severities.get(sev, 0) + 1
                verdict = f"{findings_count} findings ({severities})"
            else:
                verdict = f"JSON object: {str(data)[:200]}"
        else:
            verdict = f"NON-JSON (rc={rc}): {out[:200]} | {err[:200]}"
    except json.JSONDecodeError:
        verdict = f"PARSE_ERROR (rc={rc}): out={out[:100]} err={err[:100]}"
    print(f"  {label}: {verdict}")

# 4. Sigil
print("\n### SIGIL ###")
for label, case_dir in TEST_CASES:
    cmd = f"sigil scan {case_dir} 2>&1"
    rc, out, err = run_cmd(cmd, timeout=60)
    combined = out + err
    if "PASS" in combined or "WARN" in combined or "FAIL" in combined:
        # Count verdicts
        passes = combined.count("PASS")
        warns = combined.count("WARN")
        fails = combined.count("FAIL")
        verdict = f"{passes} PASS, {warns} WARN, {fails} FAIL"
    else:
        verdict = f"OUTPUT (rc={rc}): {combined[:200]}"
    print(f"  {label}: {verdict}")

print("\n" + "=" * 70)
print("SMOKE TEST COMPLETE")
print("=" * 70)
