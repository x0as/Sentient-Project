# Project Sentient

**Project Sentient** is an AI-powered command-line assistant designed for cybersecurity, automation, and digital forensics. First of its kind, Sentient acts as a helpful hacking AI, capable of understanding user commands and providing intelligent, conversational responses. It is modular, highly extensible, and leverages the Gemini API for advanced conversational AI—while giving the AI direct access to powerful cybersecurity, OSINT, and automation modules. This hybrid approach enables Sentient to not just chat, but to act, analyze, and automate complex security tasks far beyond standard AI assistants.

---

## Features

- **Conversational AI:** Uses Gemini API for natural, context-aware chat, but with direct access to all modules and system actions.
- **File Analysis:** Examine, edit, and understand files for suspicious content, malware, or improvements.
- **Virus Scanning:** Scan files or directories for potential malware or viruses.
- **PDF & Image Analysis:** Extract text, metadata, and scan for hidden or malicious content in PDFs and images.
- **SQL & Website Vulnerability Testing:** Scan websites for SQL injection, XSS, sensitive files, and interesting paths.
- **Traffic Sending & Imitation:** Send traffic or imitate real human traffic to websites.
- **Phishing Simulation:** Copy entire websites to demonstrate phishing attacks.
- **Malware & Virus Reverse Engineering:** Analyze and deconstruct malware or viruses.
- **Password & Key Encryption/Decryption:** Encrypt, decrypt, and crack passwords and keys.
- **Password Strength & Breach Checks:** Test password strength and check for breaches using public databases.
- **Google Dorking & OSINT:** Perform advanced search and open-source intelligence gathering.
- **Phone, Email, and Username Lookup:** Lookup and track phone numbers, emails, and usernames across platforms.
- **WHOIS, DNS, and Subdomain Enumeration:** Gather domain intelligence and enumerate subdomains.
- **Port Scanning & Directory Brute Forcing:** Scan ports and brute-force directories for hidden resources.
- **SSL/TLS Security Checks:** Analyze SSL/TLS configurations for vulnerabilities.
- **Log File Analysis:** Analyze log files for anomalies or security events.
- **Hash Generation, Identification, and Cracking:** Work with hashes for security and forensics.
- **GeoIP & Reverse IP Lookup:** Find the geographical location of IPs and enumerate domains on an IP.
- **Shodan & VirusTotal Integration:** Search Shodan and scan files/URLs with VirusTotal.
- **Username Checks & OSINT:** Check username availability and gather OSINT.
- **Packet Capture & Analysis:** Analyze network packet captures (pcap files).
- **Subdomain Takeover Detection:** Detect vulnerable subdomains.
- **CVE Search:** Search for recent vulnerabilities (CVEs) for any software or technology.
- **JWT Decoding & Analysis:** Decode and analyze JWT tokens.
- **URL Expansion & Shortening:** Expand shortened URLs and check for malicious redirects.
- **File Type Identification:** Identify file types based on content, not just extension.
- **Custom Wordlist Generation:** Generate wordlists for brute-forcing.
- **Threat Intelligence Feeds:** Pull and search latest threat intel from public feeds.
- **YARA Rule Scanning:** Scan files with YARA rules for malware detection.
- **Automated Report Generation:** Generate detailed PDF/HTML reports for scans and analyses.
- **Scheduling & Automation:** Schedule scans and recurring tasks.
- **Slack/Discord/Webhook Integration:** Send alerts or results to Slack, Discord, or via webhooks.
- **Plugin System:** Easily add your own Python modules for new features.
- **Auto-Update:** Self-update from the official repository.
- **And much more—constantly evolving to meet new threats and challenges!**

---

## Memory & Persistence

Sentient uses a MongoDB connection string (URI) to remember and store analysis results, file content, and other persistent data across sessions.  
**You will be prompted to enter your MongoDB connection string when starting Sentient.**

If you do not have a MongoDB URI or are unsure how to set one up, you can request access or assistance by emailing:  
**muhammadhuzaifakhalidaziz@gmail.com**

---

## Getting Started

1. **Clone the repository:**
   ```sh
   git clone https://github.com/yourusername/sentient.git
   cd sentient
   ```

2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

3. **Run the assistant:**
   ```sh
   python Sentient.py
   ```

4. **Configure your API key:**
   - Open `Sentient.py` and add your API key when prompted.

---

## Usage

Interact with Sentient through the command line. Type your cybersecurity or automation queries and receive intelligent responses. Type `exit` or `quit` to end the session.

**Access Key:** Google API Token.  
For full experience, email muhammadhuzaifakhalidaziz@gmail.com for a Premium Api key/Token.

---

## Example Commands

- `scan website example.com`
- `analyze file C:\path\to\file.exe`
- `email lookup test@example.com`
- `phone lookup +1234567890`
- `geoip lookup 8.8.8.8`
- `shodan search apache`
- `virustotal scan C:\path\to\file.exe`
- `jwt decode <token>`
- `cve search apache`
- `subdomain takeover example.com`
- `packet analyze C:\path\to\capture.pcap`
- `export last scan scan_results.txt`
- ...and many more!

---

## Disclaimer

This project is intended for educational and ethical cybersecurity purposes only.  
**The creator is not responsible for any misuse, illegal activity, or damage caused by the use of this software.**  
Users are solely responsible for ensuring their actions comply with all applicable laws and regulations.

---

## License

This project is licensed under the **Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License (CC BY-NC-ND 4.0)**.

- **You may not use the material for commercial purposes.**
- **You may not distribute modified versions of the project.**
- **You must give appropriate credit if you share the project.**

For more details, see [CC BY-NC-ND 4.0 License](https://creativecommons.org/licenses/by-nc-nd/4.0/)
