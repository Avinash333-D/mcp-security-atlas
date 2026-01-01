import asyncio
from mcp.server.fastmcp import FastMCP
import subprocess
import os
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

app = FastMCP("nuclei-mcp-server")

logger = logging.getLogger(__name__)

@app.tool()
async def run_nuclei_scan(target: str, templates: str = "", severity: str = "", exclude_templates: str = "", include_tags: str = "", exclude_tags: str = "", timeout: int = 300) -> str:
    """Runs Nuclei vulnerability scan on the target."""
    try:
        command = ["nuclei", "-u", target]

        if templates:
            command.extend(["-t", templates])
        if severity:
            command.extend(["-severity", severity])
        if exclude_templates:
            command.extend(["-exclude-templates", exclude_templates])
        if include_tags:
            command.extend(["-include-tags", include_tags])
        if exclude_tags:
            command.extend(["-exclude-tags", exclude_tags])

        logger.info(f"Running nuclei scan on {target} with command: {' '.join(command)}")

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        output = result.stdout
        error = result.stderr

        return f"Output:\n{output}\n\nError:\n{error}"

    except subprocess.TimeoutExpired:
        return "Nuclei scan timed out"
    except Exception as e:
        logger.error(f"Error running nuclei scan: {e}")
        return f"Error: {str(e)}"

@app.tool()
async def list_nuclei_templates() -> str:
    """Lists available Nuclei templates."""
    try:
        result = subprocess.run(
            ["nuclei", "-tl"],
            capture_output=True,
            text=True,
            timeout=60
        )

        return result.stdout

    except Exception as e:
        logger.error(f"Error listing templates: {e}")
        return f"Error: {str(e)}"

@app.tool()
async def update_nuclei_templates() -> str:
    """Updates Nuclei templates."""
    try:
        result = subprocess.run(
            ["nuclei", "-update-templates"],
            capture_output=True,
            text=True,
            timeout=300
        )

        return result.stdout

    except Exception as e:
        logger.error(f"Error updating templates: {e}")
        return f"Error: {str(e)}"

if __name__ == "__main__":
    app.run()