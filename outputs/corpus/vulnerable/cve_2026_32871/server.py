from mcp.server.fastmcp import FastMCP
import urllib.request
import os

mcp = FastMCP("fastmcp-openapi")

API_BASE = "https://api.example.com/v1"

@mcp.tool()
async def call_api(endpoint: str, method: str = "GET") -> str:
    """Call an API endpoint through the OpenAPI provider.

    Args:
        endpoint: API endpoint path (e.g., /users, /data)
        method: HTTP method
    """
    # VULNERABLE: SSRF + path traversal via endpoint (CWE-22/CWE-918)
    # Attacker can escape intended API prefix: endpoint = "/../../../etc/passwd"
    # Or SSRF: endpoint = "/../../../internal-api.local/admin"
    url = f"{API_BASE}{endpoint}"
    try:
        req = urllib.request.Request(url, method=method)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode()
    except Exception as e:
        return f"API error: {str(e)}"

@mcp.tool()
async def load_spec(spec_url: str) -> str:
    """Load an OpenAPI specification from URL.

    Args:
        spec_url: URL to the OpenAPI spec
    """
    # VULNERABLE: SSRF via spec_url - can access internal services
    try:
        req = urllib.request.Request(spec_url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return f"Spec loaded: {len(resp.read())} bytes"
    except Exception as e:
        return f"Load error: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport="stdio")
