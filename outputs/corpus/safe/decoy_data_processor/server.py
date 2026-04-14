from mcp.server.fastmcp import FastMCP
import json
import csv
import io

mcp = FastMCP("data-processor")

@mcp.tool()
async def transform_json(data: str, jq_filter: str = ".") -> str:
    """Transform JSON data with a filter expression.

    Args:
        data: JSON string to transform
        jq_filter: JQ-like filter expression
    """
    # SAFE: parses JSON safely, does not execute filters as code
    try:
        parsed = json.loads(data)
        if jq_filter == ".":
            return json.dumps(parsed, indent=2)
        elif jq_filter.startswith(".") and jq_filter[1:].isidentifier():
            key = jq_filter[1:]
            if isinstance(parsed, dict) and key in parsed:
                return json.dumps(parsed[key], indent=2)
        return "Filter not supported"
    except json.JSONDecodeError as e:
        return f"JSON parse error: {str(e)}"

@mcp.tool()
async def csv_to_json(csv_data: str) -> str:
    """Convert CSV data to JSON.

    Args:
        csv_data: CSV formatted string
    """
    # SAFE: no file system access, pure data transformation
    try:
        reader = csv.DictReader(io.StringIO(csv_data))
        return json.dumps(list(reader), indent=2)
    except Exception as e:
        return f"CSV parse error: {str(e)}"

@mcp.tool()
async def aggregate(data: str, field: str, operation: str = "sum") -> str:
    """Aggregate JSON array data by field.

    Args:
        data: JSON array string
        field: Field name to aggregate
        operation: Aggregation operation (sum/avg/count/min/max)
    """
    ALLOWED_OPS = {"sum", "avg", "count", "min", "max"}
    if operation not in ALLOWED_OPS:
        return f"Error: operation must be one of {ALLOWED_OPS}"
    try:
        records = json.loads(data)
        values = [float(r[field]) for r in records if field in r]
        if operation == "sum":
            return str(sum(values))
        elif operation == "avg":
            return str(sum(values) / len(values)) if values else "0"
        elif operation == "count":
            return str(len(values))
        elif operation == "min":
            return str(min(values)) if values else "N/A"
        elif operation == "max":
            return str(max(values)) if values else "N/A"
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport="stdio")
