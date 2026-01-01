import asyncio
from mcp.server.fastmcp import FastMCP
import subprocess
import os
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

app = FastMCP("httpx-mcp-server")

logger = logging.getLogger(__name__)

@app.tool()
async def run_httpx_probe(targets: str, title: bool = False, status_code: bool = True, tech_detect: bool = False, follow_redirects: bool = False, timeout: int = 10, retries: int = 2, threads: int = 50) -> str:
    """Runs HTTPX probe on the targets (comma-separated URLs or file path)."""
    try:
        command = ["httpx"]

        if targets.startswith("http"):
            # Assume it's a single URL or comma-separated
            command.extend(["-u", targets])
        else:
            # Assume it's a file
            command.extend(["-l", targets])

        if title:
            command.append("-title")
        if status_code:
            command.append("-status-code")
        if tech_detect:
            command.append("-tech-detect")
        if follow_redirects:
            command.append("-follow-redirects")

        command.extend(["-timeout", str(timeout), "-retries", str(retries), "-threads", str(threads)])

        logger.info(f"Running httpx probe with command: {' '.join(command)}")

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600  # 10 minutes
        )

        output = result.stdout
        error = result.stderr

        return f"Output:\n{output}\n\nError:\n{error}"

    except subprocess.TimeoutExpired:
        return "HTTPX probe timed out"
    except Exception as e:
        logger.error(f"Error running httpx probe: {e}")
        return f"Error: {str(e)}"

@app.tool()
async def run_httpx_with_custom_flags(targets: str, flags: str) -> str:
    """Runs HTTPX with custom flags on the targets."""
    try:
        command = ["httpx"] + flags.split() + ["-u", targets] if targets.startswith("http") else ["-l", targets]

        logger.info(f"Running httpx with custom flags: {' '.join(command)}")

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600
        )

        output = result.stdout
        error = result.stderr

        return f"Output:\n{output}\n\nError:\n{error}"

    except subprocess.TimeoutExpired:
        return "HTTPX timed out"
    except Exception as e:
        logger.error(f"Error running httpx: {e}")
        return f"Error: {str(e)}"

if __name__ == "__main__":
    app.run()