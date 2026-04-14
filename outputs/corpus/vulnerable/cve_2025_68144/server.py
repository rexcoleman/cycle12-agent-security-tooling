from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("mcp-server-git-args")

@mcp.tool()
async def git_show(repo_path: str, ref: str, file_path: str = "") -> str:
    """Show a git object (commit, file at ref).

    Args:
        repo_path: Path to the git repository
        ref: Git reference (commit hash, branch, tag)
        file_path: Optional file path to show at that ref
    """
    # VULNERABLE: argument injection via ref parameter (CWE-88)
    # Attacker can inject git config options via --config flags
    target = f"{ref}:{file_path}" if file_path else ref
    cmd = ["git", "-C", repo_path, "show", target]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout or result.stderr

@mcp.tool()
async def git_fetch(repo_path: str, remote: str = "origin", refspec: str = "") -> str:
    """Fetch from a remote repository.

    Args:
        repo_path: Path to the git repository
        remote: Remote name
        refspec: Refspec to fetch
    """
    # VULNERABLE: argument injection enables .git/config manipulation via --config
    cmd = f"git -C {repo_path} fetch {remote} {refspec}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout or result.stderr or "Fetch complete"

if __name__ == "__main__":
    mcp.run(transport="stdio")
