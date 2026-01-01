"""
Gmail MCP Server for security testing and reporting.
Provides endpoints for various security scans and email reporting.
"""

import os
import smtplib
import socket
import ssl
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests

# Load environment variables
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

# Configuration
GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

app = FastAPI(title="Gmail MCP Server")

# Pydantic models for FastAPI endpoints


class ScanRequest(BaseModel):
    """Request model for security scanning."""
    target: str
    email: str


class BruteForceRequest(BaseModel):
    """Request model for brute force attacks."""
    url: str
    username_field: str = "username"
    password_field: str = "password"
    usernames: list = []
    passwords: list = []
    email: str


class SQLInjectionRequest(BaseModel):
    """Request model for SQL injection testing."""
    url: str
    params: dict = {}
    email: str


class XSSRequest(BaseModel):
    """Request model for XSS testing."""
    url: str
    params: dict = {}
    email: str


class CSRFRequest(BaseModel):
    """Request model for CSRF testing."""
    url: str
    email: str


class SendReportRequest(BaseModel):
    """Request model for sending custom reports."""
    subject: str
    report: str
    email: str
    attachment_path: str = None

def send_email_report(subject: str, report: str, email: str, attachment_path: str = None):
    """Send security report via email"""
    try:
        msg = MIMEMultipart()
        msg['From'] = GMAIL_USER
        msg['To'] = email
        msg['Subject'] = subject

        msg.attach(MIMEText(report, 'plain'))

        if attachment_path and os.path.exists(attachment_path):
            with open(attachment_path, 'rb') as f:
                part = MIMEApplication(f.read(), Name=os.path.basename(attachment_path))
                part['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment_path)}"'
                msg.attach(part)

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        text = msg.as_string()
        server.sendmail(GMAIL_USER, email, text)
        server.quit()

        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def port_scan(target: str) -> str:
    """Perform comprehensive port scan using Kali MCP."""
    try:
        kali_url = os.getenv("KALI_MCP_URL", "http://localhost:8008/nmap")
        response = requests.post(kali_url,
                                json={"target": target, "options": "-p- -A -T4"},
                                timeout=600)
        if response.status_code == 200:
            data = response.json()
            return data.get("output", "") + "\n" + data.get("error", "")
        return f"Kali MCP error: {response.text}"
    except requests.exceptions.RequestException as e:
        return f"Failed to connect to Kali MCP: {str(e)}"
    except Exception as e:
        return f"Port scan error: {str(e)}"

def web_vulnerability_scan(url: str) -> str:
    """Basic web vulnerability scanning"""
    report = f"Web Vulnerability Scan Report for {url}\n"
    report += "=" * 50 + "\n\n"

    try:
        # Check SSL/TLS
        parsed_url = urlparse(url)
        if parsed_url.scheme == 'https':
            report += "SSL/TLS Analysis:\n"
            try:
                context = ssl.create_default_context()
                with socket.create_connection((parsed_url.hostname, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=parsed_url.hostname) as ssock:
                        cert = ssock.getpeercert()
                        report += f"Certificate Subject: {cert.get('subject')}\n"
                        report += f"Certificate Issuer: {cert.get('issuer')}\n"
                        report += f"Valid Until: {cert.get('notAfter')}\n"
            except Exception as e:
                report += f"SSL Error: {str(e)}\n"
            report += "\n"

        # Check for common vulnerabilities
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check for forms
        forms = soup.find_all('form')
        report += f"Found {len(forms)} forms:\n"
        for i, form in enumerate(forms):
            report += f"  Form {i+1}: action={form.get('action')}, method={form.get('method')}\n"
            inputs = form.find_all('input')
            for inp in inputs:
                report += f"    Input: {inp.get('name')} (type: {inp.get('type')})\n"
        report += "\n"

        # Check for potential XSS vulnerabilities
        scripts = soup.find_all('script')
        report += f"Found {len(scripts)} script tags\n"

        # Check headers
        report += "Security Headers:\n"
        headers = response.headers
        security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
                          'Content-Security-Policy', 'Strict-Transport-Security']
        for header in security_headers:
            if header in headers:
                report += f"  {header}: {headers[header]}\n"
            else:
                report += f"  {header}: MISSING\n"

        return report

    except Exception as e:
        return f"Web scan error: {str(e)}"

def brute_force_attack(url: str, username_field: str, password_field: str,
                      usernames: list, passwords: list) -> str:
    """Perform brute force attack on login forms"""
    report = f"Brute Force Attack Report for {url}\n"
    report += "=" * 50 + "\n\n"

    session = requests.Session()
    successful_logins = []

    for username in usernames:
        for password in passwords:
            try:
                data = {username_field: username, password_field: password}
                response = session.post(url, data=data, timeout=10)

                # Check for successful login indicators
                if response.status_code == 200 and (
                    "welcome" in response.text.lower() or
                    "dashboard" in response.text.lower() or
                    "logout" in response.text.lower() or
                    "success" in response.text.lower()
                ):
                    successful_logins.append(f"Username: {username}, Password: {password}")
                    report += f"✅ SUCCESS: {username}:{password}\n"
                    break

                time.sleep(1)  # Rate limiting

            except Exception as e:
                report += f"Error with {username}:{password} - {str(e)}\n"

    if not successful_logins:
        report += "❌ No successful logins found\n"

    return report

def sql_injection_test(url: str, params: dict) -> str:
    """Test for SQL injection vulnerabilities"""
    report = f"SQL Injection Test Report for {url}\n"
    report += "=" * 50 + "\n\n"

    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1' OR '1'='1",
        "admin' --",
        "' UNION SELECT NULL --",
        "' UNION SELECT username, password FROM users --"
    ]

    vulnerable_params = []

    for param, value in params.items():
        report += f"Testing parameter: {param}\n"
        for payload in payloads:
            try:
                test_params = params.copy()
                test_params[param] = payload

                response = requests.get(url, params=test_params, timeout=10)

                # Check for SQL error indicators
                error_indicators = [
                    "sql syntax", "mysql error", "postgresql error", "sqlite error",
                    "ora-", "microsoft sql", "syntax error", "unclosed quotation"
                ]

                response_text = response.text.lower()
                if any(indicator in response_text for indicator in error_indicators):
                    vulnerable_params.append(param)
                    report += f"  ⚠️  POTENTIAL VULNERABILITY: {param} with payload: {payload}\n"
                    break

            except Exception as e:
                report += f"  Error testing {param}: {str(e)}\n"

    if not vulnerable_params:
        report += "✅ No obvious SQL injection vulnerabilities found\n"

    return report

def xss_test(url: str, params: dict) -> str:
    """Test for XSS vulnerabilities"""
    report = f"XSS Test Report for {url}\n"
    report += "=" * 50 + "\n\n"

    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>"
    ]

    vulnerable_params = []

    for param, value in params.items():
        report += f"Testing parameter: {param}\n"
        for payload in payloads:
            try:
                test_params = params.copy()
                test_params[param] = payload

                response = requests.get(url, params=test_params, timeout=10)

                if payload in response.text:
                    vulnerable_params.append(param)
                    report += f"  ⚠️  POTENTIAL VULNERABILITY: {param} reflects input without encoding\n"
                    break

            except Exception as e:
                report += f"  Error testing {param}: {str(e)}\n"

    if not vulnerable_params:
        report += "✅ No obvious XSS vulnerabilities found\n"

    return report

def csrf_test(url: str) -> str:
    """Test for CSRF vulnerabilities"""
    report = f"CSRF Test Report for {url}\n"
    report += "=" * 50 + "\n\n"

    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        forms = soup.find_all('form')
        report += f"Analyzing {len(forms)} forms for CSRF protection:\n\n"

        for i, form in enumerate(forms):
            report += f"Form {i+1}:\n"
            report += f"  Action: {form.get('action')}\n"
            report += f"  Method: {form.get('method', 'GET')}\n"

            # Check for CSRF tokens
            csrf_indicators = ['csrf', 'token', '_token', 'authenticity_token']
            inputs = form.find_all('input')

            has_csrf = False
            for inp in inputs:
                name = inp.get('name', '').lower()
                if any(indicator in name for indicator in csrf_indicators):
                    has_csrf = True
                    report += f"  ✅ CSRF Protection Found: {inp.get('name')}\n"
                    break

            if not has_csrf:
                report += "  ⚠️  NO CSRF PROTECTION FOUND\n"

            # Check for SameSite cookies
            if 'set-cookie' in response.headers:
                cookies = response.headers['set-cookie']
                if 'samesite' in cookies.lower():
                    report += "  ✅ SameSite Cookies: Present\n"
                else:
                    report += "  ⚠️  SameSite Cookies: Missing\n"

            report += "\n"

        return report

    except Exception as e:
        return f"CSRF test error: {str(e)}"



@app.post("/sql_injection")
async def sql_injection(request: SQLInjectionRequest):
    """Test for SQL injection vulnerabilities"""
    try:
        report = sql_injection_test(request.url, request.params)

        subject = f"SQL Injection Test Report - {request.url}"
        if send_email_report(subject, report, request.email):
            return {"message": "SQL injection testing completed and report sent via email"}
        else:
            raise HTTPException(status_code=500, detail="Testing completed but email sending failed")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/xss_test")
async def xss_testing(request: XSSRequest):
    """Test for XSS vulnerabilities"""
    try:
        report = xss_test(request.url, request.params)

        subject = f"XSS Test Report - {request.url}"
        if send_email_report(subject, report, request.email):
            return {"message": "XSS testing completed and report sent via email"}
        else:
            raise HTTPException(status_code=500, detail="Testing completed but email sending failed")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/csrf_test")
async def csrf_testing(request: CSRFRequest):
    """Test for CSRF vulnerabilities"""
    try:
        report = csrf_test(request.url)

        subject = f"CSRF Test Report - {request.url}"
        if send_email_report(subject, report, request.email):
            return {"message": "CSRF testing completed and report sent via email"}
        else:
            raise HTTPException(status_code=500, detail="Testing completed but email sending failed")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/brute_force")
async def brute_force(request: BruteForceRequest):
    """Perform brute force attack and send report via email"""
    try:
        report = brute_force_attack(request.url, request.username_field, request.password_field, request.usernames, request.passwords)

        subject = f"Brute Force Attack Report - {request.url}"
        if send_email_report(subject, report, request.email):
            return {"message": "Brute force attack completed and report sent via email"}
        else:
            raise HTTPException(status_code=500, detail="Brute force completed but email sending failed")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/send_report")
async def send_custom_report(request: SendReportRequest):
    """Send a custom report via email"""
    try:
        if send_email_report(request.subject, request.report, request.email, request.attachment_path):
            return {"message": "Report sent via email"}
        else:
            raise HTTPException(status_code=500, detail="Email sending failed")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan")
async def scan_only(request: ScanRequest):
    """Perform comprehensive security testing and send report via email"""
    try:
        report = "COMPREHENSIVE SECURITY ASSESSMENT REPORT\n"
        report += f"Target: {request.target}\n"
        report += f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += "=" * 80 + "\n\n"

        # Determine if target is IP or URL
        if request.target.replace('.', '').replace('/', '').isdigit() or ':' in request.target:
            # IP address - do port scan
            report += "PORT SCAN RESULTS\n"
            report += "-" * 30 + "\n"
            report += port_scan(request.target) + "\n\n"
        else:
            # URL - do web vulnerability scan
            report += web_vulnerability_scan(request.target) + "\n\n"

        # Send email
        subject = f"Security Assessment Report - {request.target}"
        if send_email_report(subject, report, request.email):
            return {"message": "Comprehensive security assessment completed and report sent via email"}
        else:
            raise HTTPException(status_code=500, detail="Report generated but email sending failed")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("MCP_SERVER_PORT", "8002")))
