import tkinter as tk
from tkinter import messagebox
import re
import requests
import tldextract
import csv
from datetime import datetime
import os
import sys

# ---------- Configuration ----------
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")  # Securely store your key in environment variables

# ---------- Helper to Handle Resource Path (For .exe) ----------
def resource_path(relative_path):
    try:
        # When bundled into .exe by PyInstaller
        base_path = sys._MEIPASS
    except Exception:
        # When running as .py file
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# ---------- Set Log File Path (Beside .exe or .py) ----------
LOG_FILE = os.path.join(os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__), 'scan_log.csv')

# ---------- Ensure CSV Log Exists ----------
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', 'URL', 'Result'])

# ---------- URL Validity Check ----------
def is_valid_url(url):
    regex = re.compile(
        r'^(https?:\/\/)?'  # http:// or https://
        r'([\da-z\.-]+)\.([a-z\.]{2,6})'  # domain
        r'([\/\w\.-]*)*\/?$'  # path
    )
    return re.match(regex, url)

# ---------- Check if IP is used ----------
def uses_ip_address(url):
    return re.match(r'https?:\/\/\d+\.\d+\.\d+\.\d+', url)

# ---------- Check for Suspicious Keywords ----------
def contains_suspicious_keywords(url):
    keywords = ['login', 'verify', 'secure', 'update', 'free', 'click', 'signin']
    return any(word in url.lower() for word in keywords)

# ---------- Extract Domain ----------
def extract_domain_info(url):
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"

# ---------- Check URL with VirusTotal ----------
def check_with_virustotal(url):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )
        if response.status_code == 200:
            url_id = response.json()["data"]["id"]
            analysis_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{url_id}",
                headers=headers
            )
            if analysis_response.status_code == 200:
                data = analysis_response.json()
                stats = data.get("data", {}).get("attributes", {}).get("stats", {})
                return stats.get("malicious", 0) > 0
    except Exception as e:
        print("VirusTotal API error:", e)
    return False

# ---------- Log the Result ----------
def log_result(url, result):
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), url, result])

# ---------- Main Scan Logic ----------
def scan_url():
    url = url_entry.get()
    if not is_valid_url(url):
        messagebox.showwarning("Result", "Invalid URL format. Marked as unsafe.")
        log_result(url, "Invalid URL")
        return

    if uses_ip_address(url):
        messagebox.showwarning("Result", "URL uses an IP address. Suspicious!")
        log_result(url, "Suspicious (IP Address)")
        return

    domain = extract_domain_info(url)
    suspicious_domains = ["secure-login.com", "verify-now.com"]
    if domain in suspicious_domains:
        messagebox.showwarning("Result", f"Suspicious domain detected: {domain}")
        log_result(url, f"Suspicious domain: {domain}")
        return

    if contains_suspicious_keywords(url):
        messagebox.showwarning("Result", "URL contains suspicious keywords. Be careful!")
        log_result(url, "Suspicious keywords")
        return

    if check_with_virustotal(url):
        messagebox.showerror("Result", "URL is reported as malicious. Unsafe!")
        log_result(url, "Unsafe (VirusTotal)")
    else:
        messagebox.showinfo("Result", "URL appears to be safe.")
        log_result(url, "Safe")

# ---------- GUI Setup ----------
app = tk.Tk()
app.title("Phishing Link Scanner")
app.geometry("450x220")
app.resizable(False, False)

tk.Label(app, text="Enter URL to Scan:", font=("Arial", 12)).pack(pady=10)
url_entry = tk.Entry(app, width=50, font=("Arial", 10))
url_entry.pack(pady=5)

scan_button = tk.Button(app, text="Scan URL", command=scan_url, bg="black", fg="green", font=("Arial", 10))
scan_button.pack(pady=10)

app.mainloop()
