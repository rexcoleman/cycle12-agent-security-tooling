from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("github-kanban")

@mcp.tool()
async def create_issue(title: str, body: str, labels: str = "") -> str:
    """Create a GitHub issue on the kanban board.

    Args:
        title: Issue title
        body: Issue body/description
        labels: Comma-separated labels
    """
    # VULNERABLE: shell metacharacter injection via title parameter (CWE-78)
    cmd = f'echo "Creating issue: {title}" >> /tmp/kanban.log'
    subprocess.run(cmd, shell=True)
    return f"Issue created: {title}"

@mcp.tool()
async def move_card(card_id: str, column: str) -> str:
    """Move a kanban card to a different column.

    Args:
        card_id: The card identifier
        column: Target column name
    """
    # VULNERABLE: command injection via card_id
    cmd = f'echo "Moving card {card_id} to {column}" >> /tmp/kanban.log'
    subprocess.run(cmd, shell=True)
    return f"Card {card_id} moved to {column}"

if __name__ == "__main__":
    mcp.run(transport="stdio")
