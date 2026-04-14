from mcp.server.fastmcp import FastMCP
import subprocess
import shlex

mcp = FastMCP("safe-commands")

ALLOWED_COMMANDS = {"ls", "pwd", "whoami", "date", "echo"}

@mcp.tool()
async def execute_command(command: str) -> str:
    """Execute a whitelisted system command safely.

    Args:
        command: Command to execute (must be whitelisted)
    """
    parts = shlex.split(command)
    if not parts or parts[0] not in ALLOWED_COMMANDS:
        return f"Error: command {parts[0] if parts else ''} not in whitelist"
    # SAFE: uses subprocess.run without shell=True, with whitelist
    result = subprocess.run(parts, capture_output=True, text=True, timeout=5)
    return result.stdout

if __name__ == "__main__":
    mcp.run(transport="stdio")
