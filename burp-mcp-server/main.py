import asyncio
from mcp.server.fastmcp import FastMCP
import httpx
import os
from dotenv import load_dotenv
import json
import logging

# Load environment variables
load_dotenv()

# Configuration
BURP_API_BASE_URL = os.getenv("BURP_API_BASE_URL", "http://localhost:1337/v0.1/")
BURP_API_KEY = os.getenv("BURP_API_KEY")

app = FastMCP("burp-mcp-server")

logger = logging.getLogger(__name__)

@app.tool()
async def send_http1_request(content: str, target_hostname: str, target_port: int, uses_https: bool) -> str:
    """Issues an HTTP/1.1 request and returns the response."""
    endpoint = "http/send"
    params = {
        "request": content,
        "httpService": {
            "host": target_hostname,
            "port": target_port,
            "protocol": "https" if uses_https else "http"
        }
    }
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    async with httpx.AsyncClient() as client:
        response = await client.post(f"{BURP_API_BASE_URL}{endpoint}", json=params)
        response.raise_for_status()
        return response.json().get("response", "No response")

@app.tool()
async def send_http2_request(pseudo_headers: dict, headers: dict, request_body: str, target_hostname: str, target_port: int, uses_https: bool) -> str:
    """Issues an HTTP/2 request and returns the response."""
    # Similar to above, but for HTTP/2
    endpoint = "http2/send"
    params = {
        "pseudoHeaders": pseudo_headers,
        "headers": headers,
        "body": request_body,
        "httpService": {
            "host": target_hostname,
            "port": target_port,
            "protocol": "https" if uses_https else "http"
        }
    }
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    async with httpx.AsyncClient() as client:
        response = await client.post(f"{BURP_API_BASE_URL}{endpoint}", json=params)
        response.raise_for_status()
        return response.json().get("response", "No response")

@app.tool()
async def create_repeater_tab(tab_name: str, content: str, target_hostname: str, target_port: int, uses_https: bool) -> str:
    """Creates a new Repeater tab with the specified HTTP request."""
    # Assuming Burp API has a way to create repeater tab
    endpoint = "repeater/create"
    params = {
        "tabName": tab_name,
        "request": content,
        "httpService": {
            "host": target_hostname,
            "port": target_port,
            "protocol": "https" if uses_https else "http"
        }
    }
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    async with httpx.AsyncClient() as client:
        response = await client.post(f"{BURP_API_BASE_URL}{endpoint}", json=params)
        response.raise_for_status()
        return "Repeater tab created"

@app.tool()
async def send_to_intruder(tab_name: str, content: str, target_hostname: str, target_port: int, uses_https: bool) -> str:
    """Sends an HTTP request to Intruder."""
    endpoint = "intruder/send"
    params = {
        "tabName": tab_name,
        "request": content,
        "httpService": {
            "host": target_hostname,
            "port": target_port,
            "protocol": "https" if uses_https else "http"
        }
    }
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    async with httpx.AsyncClient() as client:
        response = await client.post(f"{BURP_API_BASE_URL}{endpoint}", json=params)
        response.raise_for_status()
        return "Sent to Intruder"

@app.tool()
async def url_encode(content: str) -> str:
    """URL encodes the input string."""
    endpoint = "decoder/encode"
    params = {
        "type": "url",
        "data": content
    }
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BURP_API_BASE_URL}{endpoint}", params=params)
        response.raise_for_status()
        return response.json().get("encoded", "")

@app.tool()
async def url_decode(content: str) -> str:
    """URL decodes the input string."""
    endpoint = "decoder/decode"
    params = {
        "type": "url",
        "data": content
    }
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BURP_API_BASE_URL}{endpoint}", params=params)
        response.raise_for_status()
        return response.json().get("decoded", "")

@app.tool()
async def base64_encode(content: str) -> str:
    """Base64 encodes the input string."""
    endpoint = "decoder/encode"
    params = {
        "type": "base64",
        "data": content
    }
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BURP_API_BASE_URL}{endpoint}", params=params)
        response.raise_for_status()
        return response.json().get("encoded", "")

@app.tool()
async def base64_decode(content: str) -> str:
    """Base64 decodes the input string."""
    endpoint = "decoder/decode"
    params = {
        "type": "base64",
        "data": content
    }
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BURP_API_BASE_URL}{endpoint}", params=params)
        response.raise_for_status()
        return response.json().get("decoded", "")

@app.tool()
async def generate_random_string(length: int, character_set: str) -> str:
    """Generates a random string of specified length and character set."""
    endpoint = "utilities/random_string"
    params = {
        "length": length,
        "characterSet": character_set
    }
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BURP_API_BASE_URL}{endpoint}", params=params)
        response.raise_for_status()
        return response.json().get("randomString", "")

@app.tool()
async def get_scanner_issues() -> str:
    """Displays information about issues identified by the scanner."""
    endpoint = "scanner/issues"
    params = {}
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BURP_API_BASE_URL}{endpoint}", params=params)
        response.raise_for_status()
        issues = response.json()
        return json.dumps(issues)

@app.tool()
async def get_proxy_http_history() -> str:
    """Displays items within the proxy HTTP history."""
    endpoint = "proxy/history"
    params = {}
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BURP_API_BASE_URL}{endpoint}", params=params)
        response.raise_for_status()
        history = response.json()
        # Truncate if needed
        return json.dumps(history)[:5000] + "..." if len(json.dumps(history)) > 5000 else json.dumps(history)

@app.tool()
async def set_task_execution_engine_state(running: bool) -> str:
    """Sets the state of Burp's task execution engine."""
    endpoint = "burp/task_engine"
    params = {"running": running}
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    async with httpx.AsyncClient() as client:
        response = await client.post(f"{BURP_API_BASE_URL}{endpoint}", json=params)
        response.raise_for_status()
        return f"Task execution engine set to {'running' if running else 'paused'}"

@app.tool()
async def set_proxy_intercept_state(intercepting: bool) -> str:
    """Enables or disables Burp Proxy Intercept."""
    endpoint = "proxy/intercept"
    params = {"intercepting": intercepting}
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    async with httpx.AsyncClient() as client:
        response = await client.post(f"{BURP_API_BASE_URL}{endpoint}", json=params)
        response.raise_for_status()
        return f"Intercept {'enabled' if intercepting else 'disabled'}"

@app.tool()
async def send_to_spider(url: str) -> str:
    """Sends a URL to Burp Spider for crawling."""
    endpoint = "spider/scan"
    params = {"baseUrl": url}
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(f"{BURP_API_BASE_URL}{endpoint}", json=params)
            response.raise_for_status()
            logger.info(f"Successfully sent URL {url} to Spider")
            return "Sent to Spider"
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error sending to Spider: {e}")
        return f"Error: {e}"
    except Exception as e:
        logger.error(f"Unexpected error sending to Spider: {e}")
        return f"Error: {e}"

# Add more tools as needed

if __name__ == "__main__":
    app.run()