import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

def send_email_report(subject: str, report: str, email: str):
    """Send security report via email"""
    try:
        msg = MIMEMultipart()
        msg['From'] = GMAIL_USER
        msg['To'] = email
        msg['Subject'] = subject

        msg.attach(MIMEText(report, 'plain'))

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

with open('../scan_report_192.168.56.1.txt', 'r') as f:
    report = f.read()

result = send_email_report('Detailed Scan Report for 192.168.56.1', report, 'tejaavinash431@gmail.com')

print('Email sent successfully' if result else 'Email sending failed')