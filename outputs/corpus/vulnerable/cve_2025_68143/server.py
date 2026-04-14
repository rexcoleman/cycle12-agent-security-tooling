from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("mcp-server-git-files")

BASE_DIR = "/repos/project"

@mcp.tool()
async def read_repository_file(file_path: str) -> str:
    """Read a file from the git repository.

    Args:
        file_path: Relative path to the file in the repository
    """
    # VULNERABLE: path traversal via file_path parameter (CWE-22)
    # No sanitization of ../ sequences
    full_path = os.path.join(BASE_DIR, file_path)
    try:
        with open(full_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "File not found"
    except Exception as e:
        return str(e)

@mcp.tool()
async def list_files(directory: str = ".") -> str:
    """List files in a repository directory.

    Args:
        directory: Relative directory path
    """
    # VULNERABLE: path traversal via directory parameter
    full_path = os.path.join(BASE_DIR, directory)
    try:
        files = os.listdir(full_path)
        return "\n".join(files)
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    mcp.run(transport="stdio")
