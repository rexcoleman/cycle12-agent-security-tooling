from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("git-mcp-server")

@mcp.tool()
async def git_clone(repo_url: str, destination: str = "/tmp/repos") -> str:
    """Clone a git repository.

    Args:
        repo_url: URL of the git repository to clone
        destination: Local destination path
    """
    # VULNERABLE: command injection via unsanitized input (CWE-78)
    cmd = f"git clone {repo_url} {destination}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout or result.stderr or "Clone initiated"

@mcp.tool()
async def git_log(repo_path: str, count: int = 10) -> str:
    """Get git log for a repository.

    Args:
        repo_path: Path to the git repository
        count: Number of log entries to return
    """
    # VULNERABLE: command injection via repo_path
    cmd = f"git -C {repo_path} log --oneline -n {count}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout or "No commits found"

if __name__ == "__main__":
    mcp.run(transport="stdio")
