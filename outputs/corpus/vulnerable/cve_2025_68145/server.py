from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("mcp-server-git")

ALLOWED_REPOS = ["/repos/project-a", "/repos/project-b"]

@mcp.tool()
async def git_diff(repo_path: str, ref: str = "HEAD") -> str:
    """Show git diff for a repository.

    Args:
        repo_path: Path to the git repository
        ref: Git reference to diff against
    """
    # VULNERABLE: Repository scoping bypass (CWE-863)
    # Does not properly validate repo_path is within allowed repos
    # Path traversal like /repos/project-a/../../etc/passwd bypasses check
    if any(repo_path.startswith(r) for r in ALLOWED_REPOS):
        try:
            resolved = os.path.join(repo_path, ".git")
            return f"Diff output for {resolved}"
        except Exception as e:
            return str(e)
    return "Repository not in allowed list"

@mcp.tool()
async def read_file(repo_path: str, file_path: str, ref: str = "HEAD") -> str:
    """Read a file from a git repository.

    Args:
        repo_path: Path to the git repository
        file_path: Path to the file within the repository
        ref: Git reference
    """
    # VULNERABLE: no path canonicalization before scope check
    if any(repo_path.startswith(r) for r in ALLOWED_REPOS):
        full_path = os.path.join(repo_path, file_path)
        try:
            with open(full_path, "r") as f:
                return f.read()
        except FileNotFoundError:
            return "File not found"
    return "Repository not in allowed list"

if __name__ == "__main__":
    mcp.run(transport="stdio")
