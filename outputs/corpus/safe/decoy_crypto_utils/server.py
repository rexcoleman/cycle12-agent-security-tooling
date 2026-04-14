from mcp.server.fastmcp import FastMCP
import hashlib
import hmac
import base64
import json

mcp = FastMCP("crypto-utils")

@mcp.tool()
async def hash_data(data: str, algorithm: str = "sha256") -> str:
    """Hash data using specified algorithm.

    Args:
        data: Data to hash
        algorithm: Hash algorithm (sha256/sha512/md5)
    """
    ALLOWED_ALGOS = {"sha256", "sha512", "md5", "sha1"}
    if algorithm not in ALLOWED_ALGOS:
        return f"Error: algorithm must be one of {ALLOWED_ALGOS}"
    h = hashlib.new(algorithm)
    h.update(data.encode())
    return h.hexdigest()

@mcp.tool()
async def base64_encode(data: str) -> str:
    """Base64 encode a string.

    Args:
        data: String to encode
    """
    return base64.b64encode(data.encode()).decode()

@mcp.tool()
async def base64_decode(data: str) -> str:
    """Base64 decode a string.

    Args:
        data: Base64 encoded string to decode
    """
    try:
        return base64.b64decode(data.encode()).decode()
    except Exception as e:
        return f"Decode error: {str(e)}"

@mcp.tool()
async def verify_hmac(data: str, signature: str, key: str) -> str:
    """Verify an HMAC signature.

    Args:
        data: Original data
        signature: HMAC signature to verify (hex)
        key: Secret key
    """
    expected = hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(signature, expected):
        return "Signature valid"
    return "Signature invalid"

if __name__ == "__main__":
    mcp.run(transport="stdio")
