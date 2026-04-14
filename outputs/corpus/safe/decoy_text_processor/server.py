from mcp.server.fastmcp import FastMCP
import re
import json

mcp = FastMCP("text-processor")

@mcp.tool()
async def regex_extract(text: str, pattern: str, group: int = 0) -> str:
    """Extract text matching a regex pattern.

    Args:
        text: Input text to search
        pattern: Regular expression pattern
        group: Capture group number
    """
    # SAFE: regex operations are safe (no code execution)
    try:
        matches = re.findall(pattern, text)
        return json.dumps(matches[:100])
    except re.error as e:
        return f"Regex error: {str(e)}"

@mcp.tool()
async def word_count(text: str) -> str:
    """Count words, sentences, and characters in text.

    Args:
        text: Input text
    """
    words = len(text.split())
    sentences = len(re.split(r"[.!?]+", text))
    chars = len(text)
    return json.dumps({"words": words, "sentences": sentences, "characters": chars})

@mcp.tool()
async def summarize(text: str, max_sentences: int = 3) -> str:
    """Extract first N sentences as summary.

    Args:
        text: Input text
        max_sentences: Maximum sentences in summary
    """
    sentences = re.split(r"(?<=[.!?])\s+", text)
    max_sentences = min(max(1, max_sentences), 10)
    return " ".join(sentences[:max_sentences])

if __name__ == "__main__":
    mcp.run(transport="stdio")
