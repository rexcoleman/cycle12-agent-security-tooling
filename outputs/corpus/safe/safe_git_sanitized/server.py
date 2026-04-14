from mcp.server.fastmcp import FastMCP
import subprocess
import re

mcp = FastMCP("safe-git")

ALLOWED_REPOS = ["/repos/project-a", "/repos/project-b"]

def validate_ref(ref: str) -> bool:
    """Validate git reference contains only safe characters."""
    return bool(re.match(r"^[a-zA-Z0-9._/~^-]+$", ref))

@mcp.tool()
async def git_log(repo_path: str, count: int = 10) -> str:
    """Get git log for a repository.

    Args:
        repo_path: Path to the git repository
        count: Number of log entries
    """
    # SAFE: validates repo against allowed list using realpath
    import os
    real_path = os.path.realpath(repo_path)
    if not any(real_path.startswith(os.path.realpath(r)) for r in ALLOWED_REPOS):
        return "Error: repository not in allowed list"
    # SAFE: no shell=True, uses list arguments
    count = min(max(1, count), 100)
    result = subprocess.run(["git", "-C", real_path, "log", "--oneline", f"-n{count}"], capture_output=True, text=True)
    return result.stdout or "No commits found"

if __name__ == "__main__":
    mcp.run(transport="stdio")
