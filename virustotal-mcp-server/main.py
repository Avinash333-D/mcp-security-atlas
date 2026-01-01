import asyncio
from mcp.server.fastmcp import FastMCP
import httpx
import os
from dotenv import load_dotenv
import json
import hashlib
import base64

# Load environment variables
load_dotenv()

# Configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"

app = FastMCP("virustotal-mcp-server")

@app.tool()
async def scan_url(url: str) -> str:
    """Submit a URL for VirusTotal scanning and return analysis results."""
    if not VIRUSTOTAL_API_KEY:
        return "Error: VIRUSTOTAL_API_KEY not configured"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = f"url={url}"

    async with httpx.AsyncClient() as client:
        try:
            # Submit URL for analysis
            response = await client.post(f"{VIRUSTOTAL_BASE_URL}/urls", headers=headers, content=data)
            response.raise_for_status()
            submit_result = response.json()

            analysis_id = submit_result.get("data", {}).get("id")
            if not analysis_id:
                return f"Failed to submit URL: {submit_result}"

            # Wait a moment for analysis
            await asyncio.sleep(2)

            # Get analysis results
            analysis_response = await client.get(f"{VIRUSTOTAL_BASE_URL}/analyses/{analysis_id}", headers={"x-apikey": VIRUSTOTAL_API_KEY})
            analysis_response.raise_for_status()
            analysis_data = analysis_response.json()

            # Format results
            status = analysis_data.get("data", {}).get("attributes", {}).get("status")
            stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})

            result = f"VirusTotal URL Scan Results for: {url}\n"
            result += f"Status: {status}\n"
            result += f"Malicious: {stats.get('malicious', 0)}\n"
            result += f"Suspicious: {stats.get('suspicious', 0)}\n"
            result += f"Harmless: {stats.get('harmless', 0)}\n"
            result += f"Undetected: {stats.get('undetected', 0)}\n"

            return result

        except httpx.HTTPStatusError as e:
            return f"HTTP Error: {e.response.status_code} - {e.response.text}"
        except Exception as e:
            return f"Error scanning URL: {str(e)}"

@app.tool()
async def get_url_report(url: str) -> str:
    """Get the latest VirusTotal report for a URL."""
    if not VIRUSTOTAL_API_KEY:
        return "Error: VIRUSTOTAL_API_KEY not configured"

    # First get URL ID
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{VIRUSTOTAL_BASE_URL}/urls/{url_id}", headers=headers)
            response.raise_for_status()
            data = response.json()

            attributes = data.get("data", {}).get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})

            result = f"VirusTotal Report for: {url}\n"
            result += f"Last Analysis Date: {attributes.get('last_analysis_date', 'N/A')}\n"
            result += f"Reputation: {attributes.get('reputation', 'N/A')}\n"
            result += f"Malicious: {last_analysis_stats.get('malicious', 0)}\n"
            result += f"Suspicious: {last_analysis_stats.get('suspicious', 0)}\n"
            result += f"Harmless: {last_analysis_stats.get('harmless', 0)}\n"
            result += f"Undetected: {last_analysis_stats.get('undetected', 0)}\n"

            return result

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return f"URL not found in VirusTotal database: {url}"
            return f"HTTP Error: {e.response.status_code} - {e.response.text}"
        except Exception as e:
            return f"Error getting URL report: {str(e)}"

@app.tool()
async def scan_file_hash(file_hash: str) -> str:
    """Get VirusTotal analysis report for a file hash (MD5, SHA-1, or SHA-256)."""
    if not VIRUSTOTAL_API_KEY:
        return "Error: VIRUSTOTAL_API_KEY not configured"

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}", headers=headers)
            response.raise_for_status()
            data = response.json()

            attributes = data.get("data", {}).get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})

            result = f"VirusTotal File Report for hash: {file_hash}\n"
            result += f"File Name: {attributes.get('names', ['Unknown'])[0] if attributes.get('names') else 'Unknown'}\n"
            result += f"File Size: {attributes.get('size', 'N/A')} bytes\n"
            result += f"File Type: {attributes.get('type_description', 'N/A')}\n"
            result += f"Last Analysis Date: {attributes.get('last_analysis_date', 'N/A')}\n"
            result += f"Reputation: {attributes.get('reputation', 'N/A')}\n"
            result += f"Malicious: {last_analysis_stats.get('malicious', 0)}\n"
            result += f"Suspicious: {last_analysis_stats.get('suspicious', 0)}\n"
            result += f"Harmless: {last_analysis_stats.get('harmless', 0)}\n"
            result += f"Undetected: {last_analysis_stats.get('undetected', 0)}\n"

            return result

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return f"File hash not found in VirusTotal database: {file_hash}"
            return f"HTTP Error: {e.response.status_code} - {e.response.text}"
        except Exception as e:
            return f"Error scanning file hash: {str(e)}"

@app.tool()
async def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA-256 hash of a local file for VirusTotal scanning."""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()
        return f"SHA-256 hash of {file_path}: {file_hash}"
    except FileNotFoundError:
        return f"File not found: {file_path}"
    except Exception as e:
        return f"Error calculating hash: {str(e)}"

if __name__ == "__main__":
    app.run()