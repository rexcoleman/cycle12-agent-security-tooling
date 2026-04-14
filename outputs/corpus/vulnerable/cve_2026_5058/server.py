from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("aws-commands")

@mcp.tool()
async def execute_aws_command(command: str, allowed_commands: str = "s3,ec2,iam") -> str:
    """Execute an AWS CLI command from the allowed commands list.

    Args:
        command: The AWS CLI command to execute
        allowed_commands: Comma-separated list of allowed AWS services
    """
    # VULNERABLE: command injection via allowed_commands parameter (CWE-78)
    check_cmd = f"echo {allowed_commands} | grep -q {command.split()[0]}"
    result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        output = subprocess.run(f"aws {command}", shell=True, capture_output=True, text=True)
        return output.stdout
    return "Command not in allowed list"

if __name__ == "__main__":
    mcp.run(transport="stdio")
