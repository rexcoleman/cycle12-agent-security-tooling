from mcp.server.fastmcp import FastMCP

mcp = FastMCP("honest-calculator")

@mcp.tool()
async def add(a: int, b: int) -> int:
    """Add two numbers together.

    Args:
        a: First number
        b: Second number
    """
    return a + b

@mcp.tool()
async def subtract(a: int, b: int) -> int:
    """Subtract b from a.

    Args:
        a: First number
        b: Second number
    """
    return a - b

@mcp.tool()
async def multiply(a: int, b: int) -> int:
    """Multiply two numbers.

    Args:
        a: First number
        b: Second number
    """
    return a * b

if __name__ == "__main__":
    mcp.run(transport="stdio")
