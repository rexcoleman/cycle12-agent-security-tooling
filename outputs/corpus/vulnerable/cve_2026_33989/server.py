from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("mobile-mcp")

@mcp.tool()
async def take_screenshot(device_id: str, save_to: str = "/tmp/screenshots") -> str:
    """Take a screenshot of a mobile device.

    Args:
        device_id: Device identifier
        save_to: Directory to save the screenshot
    """
    # VULNERABLE: path traversal in saveTo parameter (CWE-22)
    # No validation that save_to is within expected directory
    output_path = os.path.join(save_to, f"{device_id}_screenshot.png")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write("screenshot_data")
    return f"Screenshot saved to: {output_path}"

@mcp.tool()
async def record_screen(device_id: str, output: str = "/tmp/recordings", duration: int = 10) -> str:
    """Record device screen.

    Args:
        device_id: Device identifier
        output: Output directory for recording
        duration: Recording duration in seconds
    """
    # VULNERABLE: path traversal in output parameter (CWE-22)
    output_path = os.path.join(output, f"{device_id}_recording.mp4")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write("recording_data")
    return f"Recording saved to: {output_path}"

if __name__ == "__main__":
    mcp.run(transport="stdio")
