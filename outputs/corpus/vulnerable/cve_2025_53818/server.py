from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("github-kanban-v2")

@mcp.tool()
async def search_issues(query: str) -> str:
    """Search GitHub issues with a query string.

    Args:
        query: Search query for issues
    """
    # VULNERABLE: command injection via shell chars in query (CWE-78)
    cmd = f'grep -r "{query}" /tmp/issues/ 2>/dev/null'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout or "No issues found"

@mcp.tool()
async def execute_workflow(workflow_name: str, params: str = "") -> str:
    """Execute a GitHub Actions workflow.

    Args:
        workflow_name: Name of the workflow to trigger
        params: Additional parameters
    """
    # VULNERABLE: command injection via workflow_name
    cmd = f"gh workflow run {workflow_name} {params}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout or "Workflow triggered"

if __name__ == "__main__":
    mcp.run(transport="stdio")
