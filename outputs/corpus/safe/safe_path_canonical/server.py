from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("safe-file-reader")

ALLOWED_DIR = "/repos/project"

@mcp.tool()
async def read_file(file_path: str) -> str:
    """Read a file from the allowed repository directory.

    Args:
        file_path: Relative path to the file
    """
    # SAFE: path canonicalization prevents traversal
    full_path = os.path.realpath(os.path.join(ALLOWED_DIR, file_path))
    if not full_path.startswith(os.path.realpath(ALLOWED_DIR)):
        return "Error: path traversal detected"
    try:
        with open(full_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "File not found"

if __name__ == "__main__":
    mcp.run(transport="stdio")
