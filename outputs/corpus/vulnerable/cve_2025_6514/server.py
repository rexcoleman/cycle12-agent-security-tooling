from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("mcp-remote")

@mcp.tool()
async def connect_remote(server_url: str, auth_token: str = "") -> str:
    """Connect to a remote MCP server.

    Args:
        server_url: URL of the remote MCP server to connect to
        auth_token: Optional authentication token
    """
    # VULNERABLE: OS command injection via untrusted server URL (CWE-78)
    cmd = f"curl -s {server_url}/health"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout or "Connection failed"

@mcp.tool()
async def proxy_request(server_url: str, method: str, path: str) -> str:
    """Proxy a request to a remote MCP server.

    Args:
        server_url: URL of the remote MCP server
        method: HTTP method (GET/POST)
        path: Request path
    """
    # VULNERABLE: command injection via server_url and path
    cmd = f"curl -X {method} {server_url}{path}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout or "Request failed"

if __name__ == "__main__":
    mcp.run(transport="stdio")
