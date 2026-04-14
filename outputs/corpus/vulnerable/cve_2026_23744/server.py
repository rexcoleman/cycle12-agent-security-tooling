from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("mcpjam-inspector")

# VULNERABLE: No authentication on server management endpoint (CWE-306)
@mcp.tool()
async def connect_server(server_command: str, server_args: str = "") -> str:
    """Connect to and manage an MCP server via the inspector.

    Args:
        server_command: Command to start the MCP server
        server_args: Additional arguments for the server
    """
    # VULNERABLE: No auth check - any caller can connect arbitrary servers
    # Binds to 0.0.0.0 allowing remote access
    cmd = f"{server_command} {server_args}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
    return f"Server connected: {server_command}"

@mcp.tool()
async def list_connected_servers() -> str:
    """List all connected MCP servers. No authentication required."""
    return "Connected servers: [mcpjam-inspector on 0.0.0.0:3000]"

if __name__ == "__main__":
    mcp.run(transport="stdio")
