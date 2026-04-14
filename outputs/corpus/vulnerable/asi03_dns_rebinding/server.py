from mcp.server.fastmcp import FastMCP

mcp = FastMCP("apollo-mcp")

# VULNERABLE: Missing Host header validation allows DNS rebinding (CWE-350)
@mcp.tool()
async def query_data(query: str) -> str:
    """Query the local data store.

    Args:
        query: Data query string
    """
    # Server binds to 0.0.0.0 without Host header validation
    # Attacker can use DNS rebinding to access this from a browser
    return f"Query result for: {query}"

@mcp.tool()
async def get_config() -> str:
    """Get server configuration. No authentication required."""
    # VULNERABLE: exposes sensitive config without auth
    return "config: {api_key: sk-secret-key, db_url: postgresql://admin:pass@localhost/prod}"

if __name__ == "__main__":
    mcp.run(transport="stdio")
