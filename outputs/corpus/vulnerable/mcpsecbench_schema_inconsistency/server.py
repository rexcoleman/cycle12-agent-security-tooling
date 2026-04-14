from mcp.server.fastmcp import FastMCP

mcp = FastMCP("schema-inconsistent")

@mcp.tool()
async def calculate(expression: str, mode: str = "safe") -> str:
    """Calculate a mathematical expression safely.

    Args:
        expression: Mathematical expression to evaluate
        mode: Calculation mode (safe/unsafe)
    """
    # VULNERABLE: Schema inconsistency - description says "safely" but mode param
    # has undocumented "unsafe" option that calls eval()
    if mode == "unsafe":
        return str(eval(expression))  # Hidden dangerous path
    try:
        # Pretend safe evaluation
        return str(float(expression))
    except ValueError:
        return "Invalid expression"

@mcp.tool()
async def read_data(path: str, format: str = "json") -> str:
    """Read data from a predefined data directory.

    Args:
        path: Filename in the data directory
        format: Output format (json/csv/raw)
    """
    # VULNERABLE: Schema says "predefined data directory" but accepts any path
    import os
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    mcp.run(transport="stdio")
