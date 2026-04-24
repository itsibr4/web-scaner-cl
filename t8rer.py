import requests
import logging
import argparse
import smtplib
import json
import os
import time
import schedule
import ssl
from bs4 import BeautifulSoup
from datetime import datetime
from email.mime.text import MIMEText

CONFIG_FILE = "targets.json"
LOG_FILE = "scanner.log"
REPORT_FILE = "scan_report.html"

GMAIL_USER = "example@gmail.com"      
GMAIL_APP_PASS = "xxxx xxxx xxxx xxxx" 
RECEIVER_EMAIL = "admin@gmail.com"    

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

class WebScanner:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run

    def check_headers(self, url):
        try:
            res = requests.get(url, timeout=5)
            required = ["X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection"]
            missing = [h for h in required if h not in res.headers]
            return [f"Missing Header: {h}" for h in missing]
        except Exception as e:
            return [f"Connection Error: {str(e)}"]

    def check_xss(self, url):
        payload = "<script>alert(1)</script>"
        try:
            res = requests.get(url, params={'q': payload}, timeout=5)
            if payload in res.text:
                return ["High: Reflected XSS Detected"]
        except:
            pass
        return []

    def check_sqli(self, url):
        try:
            res = requests.get(f"{url}?id='", timeout=5)
            if "SQL syntax" in res.text or "mysql" in res.text.lower():
                return ["High: SQL Injection Detected"]
        except:
            pass
        return []

def send_alert(url, findings):
    high_issues = [i for i in findings if "High" in i]
    if not high_issues:
        return

    msg_content = f"The automated scanner found high-severity issues at {url}:\n\n" + "\n".join(high_issues)
    msg = MIMEText(msg_content)
    msg['Subject'] = f"Security Alert: Critical Issue at {url}"
    msg['From'] = GMAIL_USER
    msg['To'] = RECEIVER_EMAIL

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASS)
            server.send_message(msg)
        logging.info(f"Gmail alert sent for {url}")
        print(f"[+] Alert sent for {url}")
    except Exception as e:
        logging.error(f"Failed to send Gmail alert: {e}")
        print(f"[!] Email Error: {e}")

def create_report(data):
    html = f"<html><body><h1>Daily Report - {datetime.now().date()}</h1>"
    for url, issues in data.items():
        html += f"<h3>{url}</h3><ul>" + "".join(f"<li>{i}</li>" for i in issues) + "</ul><hr>"
    html += "</body></html>"
    with open(REPORT_FILE, "w") as f:
        f.write(html)
    print(f"[+] Report generated: {REPORT_FILE}")

def run_scanner(is_dry_run=False):
    if not os.path.exists(CONFIG_FILE):
        print(f"[!] Error: {CONFIG_FILE} not found. Please create it.")
        return

    try:
        with open(CONFIG_FILE, "r") as f:
            targets = json.load(f)
    except Exception as e:
        print(f"[!] Error parsing JSON: {e}")
        return

    scanner = WebScanner(dry_run=is_dry_run)
    all_results = {}

    for url in targets:
        print(f"[*] Scanning {url}...")
        if is_dry_run:
            print(f"[DRY-RUN] Would scan {url}")
            continue
            
        findings = scanner.check_headers(url) + scanner.check_xss(url) + scanner.check_sqli(url)
        all_results[url] = findings
        
        if findings:
            send_alert(url, findings)
            
    if not is_dry_run:
        create_report(all_results)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--now", action="store_true", help="Run the scan immediately")
    args = parser.parse_args()

    if args.now:
        print("[*] Starting manual scan...")
        run_scanner()
    else:
        print("[*] Scanner is running in scheduled mode (03:00 daily). Press Ctrl+C to stop.")
        schedule.every().day.at("03:00").do(run_scanner)
        while True:
            schedule.run_pending()
            time.sleep(60)
