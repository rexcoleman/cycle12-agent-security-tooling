#!/usr/bin/env python3
"""Test that MCP servers start and accept stdio connections."""
import subprocess
import os
import json
import sys

def test_server(server_path, timeout=5):
    """Test if a server starts and responds to MCP initialize."""
    # Send an MCP initialize request via stdin
    init_request = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }
    })

    try:
        proc = subprocess.Popen(
            [sys.executable, server_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Send initialize request
        stdout, stderr = proc.communicate(
            input=(init_request + "\n").encode(),
            timeout=timeout
        )
        stdout_text = stdout.decode()
        if "result" in stdout_text or "serverInfo" in stdout_text:
            return "OK"
        elif stdout_text.strip():
            return f"RESPONSE (no result): {stdout_text[:100]}"
        else:
            return f"NO OUTPUT, stderr: {stderr.decode()[:100]}"
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return "TIMEOUT (server started but no response to initialize)"
    except Exception as e:
        return f"ERROR: {str(e)[:100]}"

vuln_dir = os.path.expanduser("~/corpus_staging/vulnerable")
safe_dir = os.path.expanduser("~/corpus_staging/safe")

ok = 0
fail = 0
for base_dir in [vuln_dir, safe_dir]:
    label = "VULN" if "vuln" in base_dir else "SAFE"
    for case in sorted(os.listdir(base_dir)):
        server = os.path.join(base_dir, case, "server.py")
        if not os.path.exists(server):
            continue
        result = test_server(server)
        status = "OK" if result == "OK" else "ISSUE"
        if result != "OK":
            fail += 1
            print(f"  {status}: {label}/{case} - {result}")
        else:
            ok += 1

print(f"\nMCP startup test: {ok} OK, {fail} issues out of {ok + fail} total")
