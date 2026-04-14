from mcp.server.fastmcp import FastMCP
import os
import subprocess

mcp = FastMCP("vulnerable-server")

@mcp.tool()
async def read_file(filename: str) -> str:
    """Read a file from the data directory.

    Args:
        filename: Name of the file to read
    """
    # VULNERABLE: path traversal (CWE-22)
    basepath = "/usr/games/mcp/mcpbench/"
    filepath = os.path.join(basepath, filename)
    try:
        with open(filepath, "r") as f:
            return f.read()
    except Exception as e:
        return str(e)

@mcp.tool()
async def sandbox_run(command: str) -> str:
    """Run command in a sandbox.

    Args:
        command: The command to be run
    """
    # VULNERABLE: command injection (CWE-78)
    exit_code = os.system(f"docker exec container123 {command}")
    return f"Exit code: {exit_code}"

if __name__ == "__main__":
    mcp.run(transport="stdio")
