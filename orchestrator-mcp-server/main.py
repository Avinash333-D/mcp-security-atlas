from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import os
import asyncio
import uuid
from dotenv import load_dotenv
from contextlib import asynccontextmanager

# Load environment variables
load_dotenv()

# Configuration
ORCHESTRATOR_PORT = int(os.getenv("ORCHESTRATOR_PORT", 8007))
ZAP_SERVER_URL = os.getenv("ZAP_SERVER_URL", "http://localhost:8080")
BURP_SERVER_URL = os.getenv("BURP_SERVER_URL", "http://localhost:8005")
METASPLOIT_SERVER_URL = os.getenv("METASPLOIT_SERVER_URL", "http://localhost:8003")
GMAIL_SERVER_URL = os.getenv("GMAIL_SERVER_URL", "http://localhost:8002")
UNIFIED_REPORT_URL = os.getenv("UNIFIED_REPORT_URL", "http://localhost:8006")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", 60))
STEP_TIMEOUT = int(os.getenv("STEP_TIMEOUT", 120))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", 3))

# Lifespan for httpx client
@asynccontextmanager
async def lifespan(app: FastAPI):
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        app.state.client = client
        yield

app = FastAPI(title="Orchestrator MCP Server", lifespan=lifespan)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class ScanRequest(BaseModel):
    target: str
    email: str

class ScanStatus(BaseModel):
    scan_id: str
    status: str  # pending, in_progress, completed, failed
    progress: list[str]
    results: dict

# In-memory status storage
scan_statuses = {}

# Helper function to update status
def update_status(scan_id: str, status: str, progress: str = None, results: dict = None):
    if scan_id not in scan_statuses:
        scan_statuses[scan_id] = {"status": "pending", "progress": [], "results": {}}
    scan_statuses[scan_id]["status"] = status
    if progress:
        scan_statuses[scan_id]["progress"].append(progress)
    if results:
        scan_statuses[scan_id]["results"].update(results)

# Async scan functions
async def port_scan(client, scan_id, target):
    try:
        kali_url = "http://192.168.56.1:8008/nmap"
        response = await client.post(kali_url, json={"target": target, "options": "-p- -A -T4"}, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        port_scan_result = response.json()
        update_status(scan_id, "in_progress", "Port scan completed", {"port_scan": port_scan_result})
        # Parse output into findings
        findings = []
        output = port_scan_result.get("output", "")
        if "open" in output.lower():
            findings.append({
                "tool": "nmap",
                "severity": "info",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                "description": "Open ports detected",
                "url": target,
                "remediation": "Close unnecessary ports",
                "evidence": output,
                "impact": "Potential attack surface"
            })
        return findings
    except Exception as e:
        update_status(scan_id, "in_progress", f"Port scan failed: {str(e)}")
        return []

async def zap_scan(client, scan_id, target):
    try:
        # Start spider scan
        response = await client.post(f"{ZAP_SERVER_URL}/scan/start", json={"target_url": target, "scan_type": "spider"}, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        scan_data = response.json()
        scan_id_zap = scan_data.get("scan_id")
        # Wait a bit
        await asyncio.sleep(10)
        # Get alerts
        response = await client.get(f"{ZAP_SERVER_URL}/alerts", timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        alerts = response.json()
        update_status(scan_id, "in_progress", "ZAP scan completed", {"zap_alerts": alerts})
        findings = []
        for alert in alerts.get("alerts", []):
            severity = alert.get("risk", "low").lower()
            findings.append({
                "tool": "ZAP",
                "severity": severity,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",  # placeholder
                "description": alert.get("name", ""),
                "url": alert.get("url", ""),
                "remediation": alert.get("solution", ""),
                "evidence": alert.get("evidence", ""),
                "impact": alert.get("description", "")
            })
        return findings
    except Exception as e:
        update_status(scan_id, "in_progress", f"ZAP scan failed: {str(e)}")
        return []

async def burp_scan(client, scan_id, target):
    try:
        response = await client.post(f"{BURP_SERVER_URL}/scanner/scan", json={"url": target, "scan_type": "active"}, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        burp_result = response.json()
        update_status(scan_id, "in_progress", "Burp web scan completed", {"burp_scan": burp_result})
        findings = burp_result.get('findings', [])
        return findings
    except Exception as e:
        update_status(scan_id, "in_progress", f"Burp scan failed: {str(e)}")
        return []

async def gmail_scan(client, scan_id, target, email):
    try:
        response = await client.post(f"{GMAIL_SERVER_URL}/scan", json={"target": target, "email": email, "scan_type": "web"}, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        gmail_result = response.json()
        update_status(scan_id, "in_progress", "Gmail web vuln scan completed", {"gmail_scan": gmail_result})
        findings = gmail_result.get('findings', [])
        return findings
    except Exception as e:
        update_status(scan_id, "in_progress", f"Gmail scan failed: {str(e)}")
        return []

async def metasploit_scan(client, scan_id, target):
    try:
        exploit_options = {"RHOSTS": target}
        response = await client.post(f"{METASPLOIT_SERVER_URL}/exploit/run", json={"module": "exploit/windows/smb/ms17_010_eternalblue", "options": exploit_options}, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        exploit_result = response.json()
        update_status(scan_id, "in_progress", "Exploitation completed", {"exploit": exploit_result})
        findings = exploit_result.get('findings', [])
        return findings
    except Exception as e:
        update_status(scan_id, "in_progress", f"Exploitation failed: {str(e)}")
        return []

# Async function to perform scan
async def perform_scan(scan_id: str, target: str, email: str):
    client = app.state.client
    findings = []

    try:
        update_status(scan_id, "in_progress", "Starting scans")

        # Run scans in parallel
        tasks = [
            port_scan(client, scan_id, target),
            zap_scan(client, scan_id, target),
            burp_scan(client, scan_id, target),
            gmail_scan(client, scan_id, target, email),
            metasploit_scan(client, scan_id, target),
        ]
        scan_findings = await asyncio.gather(*tasks, return_exceptions=True)
        for f in scan_findings:
            if isinstance(f, list):
                findings.extend(f)

        # 4. Report aggregation and generation
        try:
            update_status(scan_id, "in_progress", "Generating report")
            # Submit findings
            response = await client.post(f"{UNIFIED_REPORT_URL}/submit-findings", json=findings)
            response.raise_for_status()
            # Generate report
            response = await client.post(f"{UNIFIED_REPORT_URL}/generate-report")
            response.raise_for_status()
            report_result = response.json()
            update_status(scan_id, "in_progress", "Report generated", {"report": report_result})
        except Exception as e:
            update_status(scan_id, "in_progress", f"Report generation failed: {str(e)}")

        # 5. Email delivery
        try:
            update_status(scan_id, "in_progress", "Sending email")
            response = await client.post(f"{UNIFIED_REPORT_URL}/send-report", json={"email": email})
            response.raise_for_status()
            update_status(scan_id, "completed", "Email sent")
        except Exception as e:
            update_status(scan_id, "completed", f"Email sending failed: {str(e)}")

    except Exception as e:
        update_status(scan_id, "failed", f"Scan failed: {str(e)}")

# Endpoints
@app.get("/")
async def root():
    return {"message": "Orchestrator MCP Server is running"}

@app.post("/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    update_status(scan_id, "pending")
    background_tasks.add_task(perform_scan, scan_id, request.target, request.email)
    return {"scan_id": scan_id, "message": "Scan started"}

@app.get("/status/{scan_id}")
async def get_status(scan_id: str):
    if scan_id not in scan_statuses:
        raise HTTPException(status_code=404, detail="Scan not found")
    status = scan_statuses[scan_id]
    return ScanStatus(scan_id=scan_id, **status)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=ORCHESTRATOR_PORT)