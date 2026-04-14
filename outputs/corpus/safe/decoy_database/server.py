from mcp.server.fastmcp import FastMCP
import sqlite3
import json

mcp = FastMCP("database-tool")

DB_PATH = "/tmp/test.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@mcp.tool()
async def query_users(name_filter: str = "", limit: int = 10) -> str:
    """Query users from the database.

    Args:
        name_filter: Filter users by name (partial match)
        limit: Maximum number of results
    """
    # SAFE: uses parameterized queries, not string interpolation
    conn = get_db()
    try:
        limit = min(max(1, limit), 100)
        if name_filter:
            rows = conn.execute("SELECT id, name, email FROM users WHERE name LIKE ? LIMIT ?",
                              (f"%{name_filter}%", limit)).fetchall()
        else:
            rows = conn.execute("SELECT id, name, email FROM users LIMIT ?", (limit,)).fetchall()
        return json.dumps([dict(r) for r in rows], indent=2)
    except Exception as e:
        return f"Query error: {str(e)}"
    finally:
        conn.close()

@mcp.tool()
async def count_records(table: str) -> str:
    """Count records in a table.

    Args:
        table: Table name (must be alphanumeric)
    """
    # SAFE: validates table name is alphanumeric
    if not table.isalnum():
        return "Error: invalid table name"
    ALLOWED_TABLES = {"users", "orders", "products"}
    if table not in ALLOWED_TABLES:
        return f"Error: table must be one of {ALLOWED_TABLES}"
    conn = get_db()
    try:
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        return str(count)
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        conn.close()

if __name__ == "__main__":
    mcp.run(transport="stdio")
