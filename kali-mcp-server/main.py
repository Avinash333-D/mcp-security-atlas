from fastapi import FastAPI, HTTPException
import subprocess
import os
from dotenv import load_dotenv
from pydantic import BaseModel
import uvicorn

load_dotenv()

app = FastAPI(title="Kali MCP Server")

class NmapRequest(BaseModel):
    target: str
    options: str = "-p- -A -T4"

class ToolRequest(BaseModel):
    command: str
    args: list = []

class NseScriptRequest(BaseModel):
    script_name: str
    target: str
    additional_options: str = ""

@app.post("/nmap")
async def run_nmap(request: NmapRequest):
    """Run nmap port scan"""
    try:
        result = subprocess.run(
            ["nmap"] + request.options.split() + [request.target],
            capture_output=True,
            text=True,
            timeout=600
        )
        output = f"Output: {result.stdout}\nError: {result.stderr}"
        return {"output": output, "error": ""}
    except subprocess.TimeoutExpired:
        return {"output": "Nmap scan timed out", "error": ""}
    except Exception as e:
        return {"output": "", "error": str(e)}

@app.post("/tool")
async def run_tool(request: ToolRequest):
    """Run a Kali tool"""
    try:
        result = subprocess.run(
            [request.command] + request.args,
            capture_output=True,
            text=True,
            timeout=300
        )
        output = f"Output: {result.stdout}\nError: {result.stderr}"
        return {"output": output, "error": ""}
    except subprocess.TimeoutExpired:
        return {"output": "Tool execution timed out", "error": ""}
    except Exception as e:
        return {"output": "", "error": str(e)}

@app.post("/run_nse_script")
async def run_nse_script(request: NseScriptRequest):
    """Run nmap NSE script"""
    try:
        command = ["nmap", "--script=" + request.script_name]
        if request.additional_options:
            command.extend(request.additional_options.split())
        command.append(request.target)
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600
        )
        output = f"Output: {result.stdout}\nError: {result.stderr}"
        return {"output": output, "error": ""}
    except subprocess.TimeoutExpired:
        return {"output": "NSE script execution timed out", "error": ""}
    except Exception as e:
        return {"output": "", "error": str(e)}

if __name__ == "__main__":
    port = int(os.getenv("KALI_PORT", "8008"))
    uvicorn.run("main:app", host="0.0.0.0", port=port)