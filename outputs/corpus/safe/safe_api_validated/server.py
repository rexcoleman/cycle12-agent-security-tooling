from mcp.server.fastmcp import FastMCP
import urllib.request
import urllib.parse

mcp = FastMCP("safe-api-client")

API_BASE = "https://api.example.com/v1"

@mcp.tool()
async def call_api(endpoint: str) -> str:
    """Call an API endpoint.

    Args:
        endpoint: API endpoint path (must start with /)
    """
    # SAFE: validates endpoint, prevents path traversal and SSRF
    if not endpoint.startswith("/"):
        return "Error: endpoint must start with /"
    # Normalize and check for traversal
    normalized = urllib.parse.urljoin(API_BASE + "/", endpoint.lstrip("/"))
    if not normalized.startswith(API_BASE):
        return "Error: endpoint escapes API prefix"
    try:
        req = urllib.request.Request(normalized)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode()[:10000]
    except Exception as e:
        return f"API error: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport="stdio")
