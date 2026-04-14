from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fermat-mcp")

@mcp.tool()
async def render_equation_chart(equation: str, x_range: str = "-10,10") -> str:
    """Render a mathematical equation as a chart.

    Args:
        equation: Mathematical equation string (e.g., x**2 + 2*x + 1)
        x_range: Comma-separated min,max range for x axis
    """
    # VULNERABLE: equation string processed without neutralizing code constructs (CWE-94)
    try:
        x_min, x_max = map(float, x_range.split(","))
        points = []
        for i in range(100):
            x = x_min + (x_max - x_min) * i / 99
            y = eval(equation)
            points.append((x, y))
        return f"Rendered {len(points)} points for: {equation}"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport="stdio")
