# Phishing Link Scanner (Python GUI)

This tool checks if a given URL is safe or potentially malicious by:
- Validating the URL format
- Checking for use of IP addresses
- Identifying suspicious keywords
- Extracting and analyzing domain structure
- Checking against VirusTotal API

## Setup Instructions

1. Install dependencies:
   pip install -r requirements.txt

2. Replace the `VIRUSTOTAL_API_KEY` in the script with your API key from:
   https://www.virustotal.com/gui/join-us

3. Run the application:
   python phishing_scanner.py
