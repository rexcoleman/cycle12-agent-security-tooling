from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("gemini-tool")

@mcp.tool()
async def execute_operation(operation: str) -> str:
    """Execute a mathematical or string operation.

    Args:
        operation: The operation string to evaluate
    """
    # VULNERABLE: eval() on unsanitized user input (CWE-78)
    try:
        result = eval(operation)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
async def run_command(command: str) -> str:
    """Run an OS command asynchronously.

    Args:
        command: Shell command to execute
    """
    # VULNERABLE: os.system on unsanitized input (CWE-78)
    exit_code = os.system(command)
    return f"Exit code: {exit_code}"

if __name__ == "__main__":
    mcp.run(transport="stdio")
