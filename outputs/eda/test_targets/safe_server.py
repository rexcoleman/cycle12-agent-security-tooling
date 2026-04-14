#!/usr/bin/env python3
"""Safe minimal MCP server - properly sanitized"""
import json
import os
import re

ALLOWED_DIR = "/tmp/mcp_safe"

def handle_tool_call(tool_name, arguments):
    if tool_name == "list_files":
        # SAFE: only lists files in allowed directory
        try:
            files = os.listdir(ALLOWED_DIR)
            return {"files": files}
        except FileNotFoundError:
            return {"files": []}
    elif tool_name == "read_safe_file":
        # SAFE: validates path is within allowed directory
        filename = arguments.get("filename", "")
        if not re.match(r"^[a-zA-Z0-9_.-]+$", filename):
            return {"error": "invalid filename"}
        filepath = os.path.join(ALLOWED_DIR, filename)
        realpath = os.path.realpath(filepath)
        if not realpath.startswith(os.path.realpath(ALLOWED_DIR)):
            return {"error": "path traversal detected"}
        with open(filepath, "r") as f:
            return {"content": f.read()}
    return {"error": "unknown tool"}

TOOLS = [
    {
        "name": "list_files",
        "description": "List files in the safe directory",
        "inputSchema": {"type": "object", "properties": {}}
    },
    {
        "name": "read_safe_file",
        "description": "Read a file from the safe directory by filename only",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Filename (no paths)"}
            },
            "required": ["filename"]
        }
    }
]

if __name__ == "__main__":
    print(json.dumps({"tools": TOOLS}, indent=2))
