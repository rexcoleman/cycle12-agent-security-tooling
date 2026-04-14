from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vegalite-server")

@mcp.tool()
async def render_chart(vegalite_specification: str) -> str:
    """Render a Vega-Lite chart from specification.

    Args:
        vegalite_specification: Vega-Lite JSON specification string
    """
    # VULNERABLE: passes specification directly to eval() (CWE-94)
    try:
        spec = eval(vegalite_specification)
        return f"Chart rendered with {len(spec)} properties"
    except Exception as e:
        return f"Render error: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport="stdio")
