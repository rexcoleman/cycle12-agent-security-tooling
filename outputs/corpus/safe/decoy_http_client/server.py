from mcp.server.fastmcp import FastMCP
import urllib.request
import urllib.parse
import json

mcp = FastMCP("http-client")

ALLOWED_HOSTS = ["api.github.com", "api.openweathermap.org", "httpbin.org"]

@mcp.tool()
async def http_get(url: str) -> str:
    """Make an HTTP GET request to an allowed host.

    Args:
        url: URL to request (must be from allowed hosts)
    """
    # SAFE: validates URL against allowlist
    parsed = urllib.parse.urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        return f"Error: host {parsed.hostname} not in allowlist"
    if parsed.scheme not in ("http", "https"):
        return "Error: only HTTP/HTTPS allowed"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "MCP-Client/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode()[:10000]
            return data
    except Exception as e:
        return f"Request error: {str(e)}"

@mcp.tool()
async def parse_json_response(json_string: str, path: str = "") -> str:
    """Parse a JSON response and extract a value.

    Args:
        json_string: JSON string to parse
        path: Dot-separated path to extract (e.g., data.name)
    """
    try:
        data = json.loads(json_string)
        if path:
            for key in path.split("."):
                if isinstance(data, dict):
                    data = data.get(key, "Key not found")
                elif isinstance(data, list) and key.isdigit():
                    data = data[int(key)]
                else:
                    return "Invalid path"
        return json.dumps(data, indent=2) if isinstance(data, (dict, list)) else str(data)
    except json.JSONDecodeError:
        return "Invalid JSON"

if __name__ == "__main__":
    mcp.run(transport="stdio")
