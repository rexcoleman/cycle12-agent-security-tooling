from mcp.server.fastmcp import FastMCP
import hashlib
import hmac

mcp = FastMCP("safe-authenticated")

API_SECRET = "server-side-secret-key"

def verify_token(token: str) -> bool:
    """Verify authentication token."""
    expected = hmac.new(API_SECRET.encode(), b"auth", hashlib.sha256).hexdigest()
    return hmac.compare_digest(token, expected)

@mcp.tool()
async def query_data(query: str, auth_token: str = "") -> str:
    """Query data with authentication required.

    Args:
        query: Data query string
        auth_token: Authentication token (required)
    """
    # SAFE: requires authentication before data access
    if not auth_token or not verify_token(auth_token):
        return "Error: authentication required"
    return f"Query result for: {query}"

@mcp.tool()
async def get_server_status() -> str:
    """Get server status (public endpoint)."""
    return "Server is running"

if __name__ == "__main__":
    mcp.run(transport="stdio")
