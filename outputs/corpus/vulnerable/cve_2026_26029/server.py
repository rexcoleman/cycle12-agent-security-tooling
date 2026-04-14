from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("sf-mcp-server")

@mcp.tool()
async def deploy_component(org_alias: str, component_path: str) -> str:
    """Deploy a Salesforce component to an org.

    Args:
        org_alias: Salesforce org alias
        component_path: Path to the component to deploy
    """
    # VULNERABLE: command injection via user-controlled input (CWE-78)
    cmd = f"sf project deploy start --source-dir {component_path} --target-org {org_alias}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout or "Deploy initiated"

@mcp.tool()
async def run_apex(org_alias: str, apex_code: str) -> str:
    """Execute anonymous Apex code on a Salesforce org.

    Args:
        org_alias: Salesforce org alias
        apex_code: Apex code to execute
    """
    # VULNERABLE: direct shell injection via apex_code
    cmd = f"sf apex run --target-org {org_alias} --file /dev/stdin"
    result = subprocess.run(cmd, shell=True, input=apex_code, capture_output=True, text=True)
    return result.stdout or result.stderr

if __name__ == "__main__":
    mcp.run(transport="stdio")
