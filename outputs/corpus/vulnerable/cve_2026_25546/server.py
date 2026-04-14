from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("godot-mcp")

@mcp.tool()
async def execute_operation(project_path: str, operation: str = "build") -> str:
    """Execute a Godot project operation.

    Args:
        project_path: Path to the Godot project
        operation: Operation to perform (build/run/export)
    """
    # VULNERABLE: projectPath passed directly to exec() (CWE-78)
    cmd = f"godot --path {project_path} --{operation}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout or result.stderr

if __name__ == "__main__":
    mcp.run(transport="stdio")
