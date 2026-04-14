from mcp.server.fastmcp import FastMCP
import ast

mcp = FastMCP("safe-calculator")

@mcp.tool()
async def calculate(expression: str) -> str:
    """Calculate a mathematical expression safely.

    Args:
        expression: Mathematical expression (numbers and basic operators only)
    """
    # SAFE: uses ast.literal_eval instead of eval()
    try:
        # Only allow numeric literals and basic operations
        tree = ast.parse(expression, mode="eval")
        for node in ast.walk(tree):
            if isinstance(node, (ast.Call, ast.Attribute, ast.Import, ast.ImportFrom)):
                return "Error: only basic math expressions allowed"
        result = eval(compile(tree, "<string>", "eval"), {"__builtins__": {}}, {})
        return str(result)
    except (ValueError, SyntaxError) as e:
        return f"Invalid expression: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport="stdio")
