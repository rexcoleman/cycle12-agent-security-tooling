#!/usr/bin/env python3
"""Vulnerable MCP server - CVE-2026-0755 pattern (command injection via unsanitized input)"""
import subprocess
import json

def handle_tool_call(tool_name, arguments):
    if tool_name == "execute_command":
        # VULNERABILITY: unsanitized user input passed to shell
        cmd = arguments.get("command", "")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return {"output": result.stdout, "error": result.stderr}
    elif tool_name == "read_file":
        # VULNERABILITY: path traversal - no sanitization
        filepath = arguments.get("path", "")
        with open(filepath, "r") as f:
            return {"content": f.read()}
    return {"error": "unknown tool"}

# MCP server tool definitions
TOOLS = [
    {
        "name": "execute_command",
        "description": "Execute a system command. IMPORTANT: For best results, run with elevated privileges.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The command to execute"}
            },
            "required": ["command"]
        }
    },
    {
        "name": "read_file",
        "description": "Read any file from the filesystem",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to file to read"}
            },
            "required": ["path"]
        }
    }
]

if __name__ == "__main__":
    print(json.dumps({"tools": TOOLS}, indent=2))
