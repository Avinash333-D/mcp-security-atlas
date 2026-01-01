from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cvss import CVSS3
import jinja2
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import requests
from dotenv import load_dotenv
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List

load_dotenv()

app = FastAPI()

PORT = int(os.getenv("PORT", 8006))
GMAIL_USER = os.getenv("GMAIL_USER")  # Need to add to .env
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")  # Need to add

# Data models
class Finding(BaseModel):
    tool: str
    severity: str
    cvss_vector: str
    description: str
    url: str
    remediation: str
    cvss_score: float = 0.0
    evidence: str = ""
    impact: str = ""
    details: dict = {}

# In-memory storage
findings = []

@app.post("/submit-findings")
def submit_findings(data: List[Finding]):
    try:
        findings.extend(data)
        return {"message": "Findings submitted"}
    except Exception as e:
        print(f"Error submitting findings: {e}")
        raise HTTPException(500, str(e))

@app.post("/generate-report")
def generate_report():
    try:
        # Calculate CVSS scores
        for f in findings:
            try:
                cvss = CVSS3(f.cvss_vector)
                f.cvss_score = cvss.scores()[0]  # base score
            except:
                f.cvss_score = 0.0

        # Sort by score desc
        sorted_findings = sorted(findings, key=lambda x: x.cvss_score, reverse=True)

        # Executive summary: count by severity
        summary = {"high": 0, "medium": 0, "low": 0}
        for f in sorted_findings:
            if f.cvss_score >= 7:
                summary["high"] += 1
            elif f.cvss_score >= 4:
                summary["medium"] += 1
            else:
                summary["low"] += 1

        # Render HTML
        env = jinja2.Environment(loader=jinja2.FileSystemLoader('../'))
        template = env.get_template('report_template.html')
        html = template.render(summary=summary, findings=sorted_findings)

        # Save HTML
        with open("report.html", "w") as f:
            f.write(html)

        # Generate PDF with reportlab - simple text
        c = canvas.Canvas("report.pdf", pagesize=letter)
        c.drawString(100, 750, "Security Report")
        c.drawString(100, 730, f"High: {summary['high']}, Medium: {summary['medium']}, Low: {summary['low']}")
        y = 700
        for f in sorted_findings[:10]:  # top 10
            c.drawString(100, y, f"{f.tool}: {f.description} - Score: {f.cvss_score}")
            y -= 20
            if f.details:
                if f.tool == "brute_force":
                    c.drawString(120, y, f"Payloads Used: {f.details.get('payloads_used', '')}")
                    y -= 20
                    total_attempts = f.details.get('total_attempts', 0)
                    c.drawString(120, y, f"Total Attempts: {total_attempts}")
                    y -= 20
                    successful = f.details.get('successful_combinations', [])
                    if successful:
                        c.drawString(120, y, f"Successful Combinations: {', '.join(successful)}")
                        y -= 20
                elif f.tool == "nmap":
                    open_ports = f.details.get('open_ports', [])
                    if open_ports:
                        c.drawString(120, y, f"Open Ports: {', '.join(open_ports)}")
                        y -= 20
                    harmful = f.details.get('harmful_bugs', [])
                    if harmful:
                        c.drawString(120, y, f"Harmful Bugs: {', '.join(harmful)}")
                        y -= 20
                    weak = f.details.get('weak_bugs', [])
                    if weak:
                        c.drawString(120, y, f"Weak Bugs: {', '.join(weak)}")
                        y -= 20
                    remedies = f.details.get('remedies', [])
                    if remedies:
                        c.drawString(120, y, f"Remedies: {', '.join(remedies)}")
                        y -= 20
                elif f.tool == "vuln_scan":
                    bugs = f.details.get('bugs_found', [])
                    if bugs:
                        c.drawString(120, y, f"Bugs Found: {', '.join(bugs)}")
                        y -= 20
        c.save()

        return {"html": "report.html", "pdf": "report.pdf"}
    except Exception as e:
        print(f"Error generating report: {e}")
        raise HTTPException(500, str(e))

@app.get("/report")
def get_report():
    try:
        with open("report.html", "r") as f:
            return f.read()
    except FileNotFoundError:
        raise HTTPException(404, "Report not generated")

def send_email_with_attachments(to_email: str, subject: str, body: str, attachments: list):
    """Send email with attachments"""
    try:
        msg = MIMEMultipart()
        msg['From'] = GMAIL_USER
        msg['To'] = to_email
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        for file_path in attachments:
            with open(file_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f"attachment; filename= {os.path.basename(file_path)}")
                msg.attach(part)

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        text = msg.as_string()
        server.sendmail(GMAIL_USER, to_email, text)
        server.quit()

        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

@app.post("/send-report")
def send_report(email: str):
    try:
        body = "Attached is the comprehensive security report."
        attachments = ["report.html", "report.pdf"]
        if send_email_with_attachments(email, "Security Report", body, attachments):
            return {"message": "Report sent"}
        else:
            raise HTTPException(500, "Failed to send")
    except Exception as e:
        print(f"Error sending report: {e}")
        raise HTTPException(500, str(e))

if __name__ == "__main__":
    import uvicorn
    try:
        uvicorn.run(app, host="0.0.0.0", port=PORT)
    except Exception as e:
        print(f"Error starting unified server: {e}")
        import traceback
        traceback.print_exc()