import os
import sys
import time
import shutil
import threading
import requests
import google.generativeai as genai
from pymongo import MongoClient
import shlex
from tabulate import tabulate
from fuzzywuzzy import fuzz
import re

from .modules.traffic_sender import send_traffic
from .modules.real_traffic import imitate_real_traffic
from .modules.file_analysis import analyze_file
from .modules import Phone_Lookup
from .modules import Email_Lookup
from .modules import Email_Tracker
from .modules import website_scanner
from .modules import whois_lookup
from .modules import subdomain_enum
from .modules import port_scanner
from .modules import dir_bruteforce
from .modules import hash_tools
from .modules import ssl_checker
from .modules import dns_tools
from .modules import email_spoof_test
from .modules import log_analyzer


SENTIENT_COLOR = "\033[96m"
RESET_COLOR = "\033[0m"
ERROR_COLOR = "\033[91m"
INFO_COLOR = "\033[93m"
SUCCESS_COLOR = "\033[92m"
WARNING_COLOR = "\033[93m"

def print_banner_rainbow_until_enter():
    colors = [
        "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[94m", "\033[95m"
    ]
    RESET_COLOR = "\033[0m"
    art = [
        "      #######                                                                         ",
        "    /       ###                                   #                                   ",
        "   /         ##                           #      ###                            #     ",
        "   ##        #                           ##       #                            ##     ",
        "    ###                                  ##                                    ##     ",
        "   ## ###           /##  ###  /###     ######## ###       /##  ###  /###     ######## ",
        "    ### ###        / ###  ###/ #### / ########   ###     / ###  ###/ #### / ########  ",
        "      ### ###     /   ###  ##   ###/     ##       ##    /   ###  ##   ###/     ##     ",
        "        ### /##  ##    ### ##    ##      ##       ##   ##    ### ##    ##      ##     ",
        "           #/ ## #######   ##    ##      ##       ##   #######   ##    ##      ##    ",
        "            # /  ##        ##    ##      ##       ##   ##        ##    ##      ##    ",
        "  /##        /   ####    / ##    ##      ##       ##   ####    / ##    ##      ##    ",
        " /  ########/     ######/  ###   ###     ##       ### / ######/  ###   ###     ##    ",
        "/     #####        #####    ###   ###     ##       ##/   #####    ###   ###     ##   ",
        "                                                                                      ",
        "                                                                                      ",
    ]
    prompt = "Press Enter to start"
    try:
        columns = shutil.get_terminal_size().columns
    except Exception:
        columns = 100
    stop_animation = threading.Event()
    def wait_for_enter():
        if os.name == 'nt':
            import msvcrt
            msvcrt.getch()
        else:
            input()
        stop_animation.set()
    t = threading.Thread(target=wait_for_enter, daemon=True)
    t.start()
    color_idx = 0
    while not stop_animation.is_set():
        os.system('cls' if os.name == 'nt' else 'clear')
        color = colors[color_idx % len(colors)]
        for line in art:
            print(color + line.center(columns) + RESET_COLOR)
        print("\n" * 2)
        print(f"{color}{prompt.center(columns)}{RESET_COLOR}")
        time.sleep(0.13)
        color_idx += 1
    os.system('cls' if os.name == 'nt' else 'clear')
    for line in art:
        print("\033[96m" + line.center(columns) + RESET_COLOR)
    print("\n" * 2)
    print(f"\033[96m{prompt.center(columns)}{RESET_COLOR}")

def auto_update_check():
    GITHUB_RAW_URL = "https://raw.githubusercontent.com/x0as/Sentient/main/Sentient.py"
    try:
        print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Checking for updates...")
        response = requests.get(GITHUB_RAW_URL, timeout=10)
        if response.status_code == 200:
            with open(__file__, "r", encoding="utf-8") as f:
                current_code = f.read()
            if response.text.strip() != current_code.strip():
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Update found. Installing update...")
                with open(__file__, "w", encoding="utf-8") as f:
                    f.write(response.text)
                print(f"{SUCCESS_COLOR}[Sentient]{RESET_COLOR} Update installed. Please restart Sentient.")
                sys.exit(0)
            else:
                print(f"{SUCCESS_COLOR}[Sentient]{RESET_COLOR} You are running the latest version.")
        else:
            print(f"{ERROR_COLOR}[Sentient]{RESET_COLOR} Could not check for updates (HTTP {response.status_code}).")
    except Exception as e:
        print(f"{ERROR_COLOR}[Sentient]{RESET_COLOR} Update check failed: {e}")

def extract_command(user_input):
    user_input_lower = user_input.lower()
    patterns = [
        ("scan website", ["vulnerabilities", "scan", "find"], r"(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"),
        ("phone lookup", ["phone", "number", "lookup"], r"\+?\d[\d\s\-]{7,}"),
        ("email lookup", ["email", "lookup"], r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
        ("email tracker", ["email", "tracker", "track"], r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
        ("send traffic", ["send", "traffic"], r"(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"),
        ("imitate traffic", ["imitate", "traffic"], r"(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"),
        ("analyze file content", ["analyze", "file", "content"], r'"([^"]+)"|([^\s]+)'),
        ("analyze file", ["analyze", "file"], r'"([^"]+)"|([^\s]+)'),
        ("whois", ["whois"], r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        ("subdomain enum", ["subdomain", "enum", "enumerate"], r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        ("scan ports", ["scan", "ports", "port"], r"[a-zA-Z0-9.-]+"),
        ("dir brute", ["dir", "directory", "brute"], r"(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"),
        ("identify hash", ["identify", "hash"], r"\b[a-fA-F0-9]{8,}\b"),
        ("crack hash", ["crack", "hash"], r"\b[a-fA-F0-9]{8,}\b"),
        ("check ssl", ["ssl", "tls", "check"], r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        ("dns lookup", ["dns", "lookup"], r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        ("test email spoofing", ["spoof", "email", "test"], r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
        ("analyze log", ["analyze", "log"], r'"([^"]+)"|([^\s]+)'),
        ("export last scan", ["export", "scan"], r"[^\s]+"),
        ("export last file analysis", ["export", "file", "analysis"], r"[^\s]+"),
    ]
    for intent, keywords, arg_regex in patterns:
        if all(word in user_input_lower for word in keywords):
            match = re.search(arg_regex, user_input)
            if match:
                # Support quoted or unquoted
                return intent, match.group(1) or match.group(2) if match.lastindex else match.group(0)
    for intent, keywords, arg_regex in patterns:
        for word in keywords:
            if word in user_input_lower:
                match = re.search(arg_regex, user_input)
                if match:
                    return intent, match.group(1) or match.group(2) if match.lastindex else match.group(0)
    return None, None

def main():
    auto_update_check()
    print_banner_rainbow_until_enter()
    api_key = input("Enter your Access Key: ").strip()
    mongo_uri = input("Enter your MongoDB connection string (URI): ").strip()
    client = MongoClient(mongo_uri)
    db = client["sentient_db"]
    files_collection = db["analyzed_files"]

    genai.configure(api_key=api_key)

    available_models = [
        m for m in genai.list_models()
        if hasattr(m, "supported_generation_methods") and "generateContent" in m.supported_generation_methods
    ]
    preferred_model = None
    for m in available_models:
        if "gemini-1.5-flash" in m.name:
            preferred_model = m
            break
    if not preferred_model and available_models:
        preferred_model = available_models[0]
    if not preferred_model:
        print(f"{ERROR_COLOR}[Sentient]{RESET_COLOR} No compatible generative models available for your API key.")
        return
    model = genai.GenerativeModel(preferred_model.name)

    system_prompt = (
        "You are Sentient, an advanced AI CLI assistant created by x0as. "
        "You can now do the following: "
        "Analyze files, scan for viruses, test websites for SQL vulnerabilities, "
        "send or imitate traffic, perform email lookups (email lookup <email>), "
        "track email usage across platforms (email tracker <email>), "
        "perform phone number lookups (phone lookup <number>), "
        "perform WHOIS lookups (whois <domain>), "
        "enumerate subdomains (subdomain enum <domain>), "
        "scan ports (scan ports <host>), "
        "brute force directories (dir brute <url>), "
        "identify and crack hashes (identify hash <hash>, crack hash <hash>), "
        "check SSL/TLS security (check ssl <domain>), "
        "perform DNS lookups (dns lookup <domain>), "
        "test email spoofing (test email spoofing <email>), "
        "analyze log files (analyze log <filepath>), "
        "export scan and analysis reports to files, "
        "auto-update itself from the official repository, "
        "answer follow-up questions about previous scans or file analyses, "
        "display a glowing animated ASCII art banner on startup, "
        "use fuzzy matching to understand natural language commands, "
        "and support broad, flexible command recognition (e.g., you understand requests like 'find vulnerabilities in example.com for me'). "
        "Respond concisely and directly. Only ask questions if more information is required to execute a command. "
        "Be slightly talkative, but not too much and not too little. "
        "You are powered by x0as's own API and are not affiliated with Google or Gemini."
    )

    print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} AI CLI (x0as) (type 'exit' to quit)")
    print(f"{ERROR_COLOR}Security Notice:{RESET_COLOR} Use Sentient responsibly. Only scan, test, or analyze systems you own or have explicit permission to access. Unauthorized use may be illegal and unethical.\n")
    pending_confirmation = None
    last_file_content = None
    last_file_path = None
    last_scan_results = None
    last_scan_url = None

    while True:
        user_input = input("You: ")
        if user_input.lower() in ["exit", "quit"]:
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Goodbye! If you need more cybersecurity help, just start me up again. Stay safe out there!")
            break

        # Help command and security notice
        if user_input.lower() in ["help", "commands", "what can you do", "how to use", "usage"]:
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Here are some things I can do:")
            for intent, _, _ in [
                ("export last scan", ["export", "scan"], r"[^\s]+"),
                ("export last file analysis", ["export", "file", "analysis"], r"[^\s]+"),
                ("scan website", ["vulnerabilities", "scan", "find"], r"(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"),
                ("phone lookup", ["phone", "number", "lookup"], r"\+?\d[\d\s\-]{7,}"),
                ("email lookup", ["email", "lookup"], r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
                ("email tracker", ["email", "tracker", "track"], r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
                ("send traffic", ["send", "traffic"], r"(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"),
                ("imitate traffic", ["imitate", "traffic"], r"(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"),
                ("analyze file content", ["analyze", "file", "content"], r"[^\s]+"),
                ("analyze file", ["analyze", "file"], r"[^\s]+"),
                ("whois", ["whois"], r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
                ("subdomain enum", ["subdomain", "enum", "enumerate"], r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
                ("scan ports", ["scan", "ports", "port"], r"[a-zA-Z0-9.-]+"),
                ("dir brute", ["dir", "directory", "brute"], r"(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"),
                ("identify hash", ["identify", "hash"], r"\b[a-fA-F0-9]{8,}\b"),
                ("crack hash", ["crack", "hash"], r"\b[a-fA-F0-9]{8,}\b"),
                ("check ssl", ["ssl", "tls", "check"], r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
                ("dns lookup", ["dns", "lookup"], r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
                ("test email spoofing", ["spoof", "email", "test"], r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
                ("analyze log", ["analyze", "log"], r"[^\s]+"),
            ]:
                print(f"  {intent}")
            print(f"\nType a command as shown above or just describe what you want. For example: 'find vulnerabilities in example.com' or 'check ssl github.com'.")
            print(f"\n{INFO_COLOR}Security Notice:{RESET_COLOR} Use Sentient responsibly and only on systems you own or have permission to test. Unauthorized use may be illegal and unethical.")
            continue

        matched_command, argument = extract_command(user_input)

        # Existing core commands below...

        if matched_command == "export last scan":
            if not last_scan_results:
                print(f"{ERROR_COLOR}[Sentient]{RESET_COLOR} No scan results to export.")
                continue
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: export last scan <filename>")
                continue
            try:
                with open(argument, "w", encoding="utf-8") as f:
                    for k, v in last_scan_results.items():
                        f.write(f"{k}: {v}\n")
                print(f"{SUCCESS_COLOR}[Sentient]{RESET_COLOR} Last scan results exported to {argument}")
            except Exception as e:
                print(f"{ERROR_COLOR}[Sentient]{RESET_COLOR} Failed to export: {e}")
            continue

        if matched_command == "export last file analysis":
            if not last_file_content or not last_file_path:
                print(f"{ERROR_COLOR}[Sentient]{RESET_COLOR} No file analysis to export.")
                continue
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: export last file analysis <filename>")
                continue
            try:
                with open(argument, "w", encoding="utf-8") as f:
                    f.write(f"File: {last_file_path}\n\n{last_file_content}")
                print(f"{SUCCESS_COLOR}[Sentient]{RESET_COLOR} Last file analysis exported to {argument}")
            except Exception as e:
                print(f"{ERROR_COLOR}[Sentient]{RESET_COLOR} Failed to export: {e}")
            continue

        if matched_command in ["scan website"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: scan website <url>")
                continue
            url = argument
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Initiating website scan for vulnerabilities on {url}. This may take some time. Report will be provided upon completion.")
            scan_results = website_scanner.website_vulnerability_scan_cli_with_url(url, return_results=True)
            last_scan_results = scan_results
            last_scan_url = url
            continue

        if matched_command in ["phone lookup"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: phone lookup <number>")
                continue
            phone = argument
            result = Phone_Lookup.phone_lookup_cli(phone)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Phone Lookup Result:")
            for k, v in result.items():
                print(f"  {k}: {v}")
            continue

        if matched_command in ["email lookup"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: email lookup <email>")
                continue
            email = argument
            try:
                result = Email_Lookup.email_lookup_cli(email)
                print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Email Lookup Result:")
                for k, v in result.items():
                    print(f"  {k}: {v}")
            except Exception as e:
                print(f"{ERROR_COLOR}[Sentient]{RESET_COLOR} Error during email lookup: {e}")
            continue

        if matched_command in ["email tracker"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: email tracker <email>")
                continue
            email = argument
            try:
                result = Email_Tracker.email_tracker_cli(email)
                if isinstance(result, dict):
                    print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Email Tracker Result:")
                    for k, v in result.items():
                        print(f"  {k}: {v}")
            except Exception as e:
                print(f"{ERROR_COLOR}[Sentient]{RESET_COLOR} Error during email tracking: {e}")
            continue

        if matched_command in ["send traffic"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: send traffic <url> <count>")
                continue
            url = argument
            count_match = re.search(r"\b(\d+)\b", user_input)
            count = int(count_match.group(1)) if count_match else 1
            result = send_traffic(url, count)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} {result}")
            continue

        if matched_command in ["imitate traffic"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: imitate traffic <url> <count>")
                continue
            url = argument
            count_match = re.search(r"\b(\d+)\b", user_input)
            count = int(count_match.group(1)) if count_match else 1
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Simulating {count} real browser visits to {url}. This may take time and impact the target server. Proceed? (y/n)")
            pending_confirmation = (url, count)
            continue

        if matched_command in ["analyze file content"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: analyze file content <filepath>")
                continue
            filepath = argument
            result = analyze_file(filepath, include_content=True)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} {result}")
            if "--- File Content" in result:
                last_file_content = result.split("--- File Content", 1)[-1]
                last_file_path = filepath
                files_collection.update_one(
                    {"filepath": filepath},
                    {"$set": {
                        "filepath": filepath,
                        "content": last_file_content,
                    }},
                    upsert=True
                )
                prompt = (
                    f"{system_prompt}\nBelow is the content of the file '{filepath}'. "
                    f"Please answer the user's question about this file using ONLY the content provided. "
                    f"If the question is about viruses or malware, analyze the code/text for any signs of malicious behavior. "
                    f"\n\n--- File Content Start ---\n{last_file_content}\n--- File Content End ---\n"
                    f"What can you tell me about this file?"
                )
                response = model.generate_content(prompt)
                print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} {response.text.strip()}")
            continue

        if matched_command in ["analyze file"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: analyze file <filepath>")
                continue
            filepath = argument
            result = analyze_file(filepath)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} {result}")
            continue

        if matched_command in ["whois"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: whois <domain>")
                continue
            domain = argument
            result = whois_lookup.whois_lookup_cli(domain)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} WHOIS Result:")
            for k, v in result.items():
                print(f"  {k}: {v}")
            continue

        if matched_command in ["subdomain enum"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: subdomain enum <domain>")
                continue
            domain = argument
            found = subdomain_enum.subdomain_enum_cli(domain)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Subdomains found:")
            if found:
                for sub in found:
                    print(f"  {sub}")
            else:
                print("  None found.")
            continue

        if matched_command in ["scan ports"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: scan ports <host>")
                continue
            host = argument
            open_ports = port_scanner.port_scan_cli(host)
            if open_ports:
                table = [[port, "open"] for port in open_ports]
                print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Open Ports:\n" + tabulate(table, headers=["Port", "Status"], tablefmt="fancy_grid"))
            else:
                print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} No open ports found.")
            continue

        if matched_command in ["dir brute"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: dir brute <url>")
                continue
            url = argument
            found = dir_bruteforce.dir_bruteforce_cli(url)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Directories found:")
            if found:
                for d in found:
                    print(f"  {d}")
            else:
                print("  None found.")
            continue

        if matched_command in ["identify hash"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: identify hash <hash>")
                continue
            hash_str = argument
            hash_type = hash_tools.identify_hash(hash_str)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Hash type: {hash_type}")
            continue

        if matched_command in ["crack hash"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: crack hash <hash>")
                continue
            hash_str = argument
            result = hash_tools.crack_hash(hash_str)
            if result:
                print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Hash cracked! Value: {result}")
            else:
                print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Could not crack the hash with the default wordlist.")
            continue

        if matched_command in ["check ssl"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: check ssl <domain>")
                continue
            domain = argument
            result = ssl_checker.check_ssl(domain)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} SSL Info:")
            for k, v in result.items():
                print(f"  {k}: {v}")
            continue

        if matched_command in ["dns lookup"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: dns lookup <domain>")
                continue
            domain = argument
            results = dns_tools.dns_lookup(domain)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} DNS Lookup Results:")
            for r in results:
                print(f"  {r}")
            continue

        if matched_command in ["test email spoofing"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: test email spoofing <email>")
                continue
            email = argument
            result = email_spoof_test.test_email_spoofing(email)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Spoofing Test Result: {result}")
            continue

        if matched_command in ["analyze log"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: analyze log <filepath>")
                continue
            filepath = argument
            results = log_analyzer.analyze_log(filepath)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Log Analysis Results:")
            for r in results:
                print(f"  {r}")
            continue

        if pending_confirmation:
            if user_input.lower() == "y":
                url, count = pending_confirmation
                result = imitate_real_traffic(url, count)
                print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} {result}")
                pending_confirmation = None
                continue
            elif user_input.lower() == "n":
                print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Cancelled.")
                pending_confirmation = None
                continue
            else:
                print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Please reply with 'y' or 'n'.")
                continue

        if last_file_content and not any(
            user_input.startswith(cmd) for cmd in [
                "analyze file", "analyze file content", "send traffic",
                "imitate traffic", "immitate real traffic", "email lookup",
                "email tracker", "phone lookup", "scan website"
            ]
        ):
            prompt = (
                f"{system_prompt}\nBelow is the content of the file '{last_file_path}'. "
                f"Please answer the user's question about this file using ONLY the content provided. "
                f"If the question is about viruses or malware, analyze the code/text for any signs of malicious behavior. "
                f"\n\n--- File Content Start ---\n{last_file_content}\n--- File Content End ---\n"
                f"User's follow-up question: {user_input}"
            )
            response = model.generate_content(prompt)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} {response.text.strip()}")
            continue

        if last_scan_results and (
            any(word in user_input.lower() for word in [
                "scan", "vulnerability", "website", "sql", "xss", "cross site", "paths", "files", "results"
            ])
            and (not matched_command or matched_command not in ["scan website"])
        ):
            scan_context = (
                f"Website vulnerability scan results for {last_scan_url}:\n"
                f"SQL Injection: {last_scan_results.get('sql') or 'None'}\n"
                f"XSS: {last_scan_results.get('xss') or 'None'}\n"
                f"Interesting Paths: {last_scan_results.get('paths') or 'None'}\n"
                f"Sensitive Files: {last_scan_results.get('files') or 'None'}\n"
            )
            prompt = (
                f"{system_prompt}\n"
                f"{scan_context}\n"
                f"User's follow-up question about the scan: {user_input}\n"
                f"Please answer using ONLY the scan results above."
            )
            response = model.generate_content(prompt)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} {response.text.strip()}")
            continue

        try:
            prompt = f"{system_prompt}\nUser: {user_input}"
            response = model.generate_content(prompt)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} {response.text.strip()}")
        except Exception as e:
            print(f"{ERROR_COLOR}[Sentient]{RESET_COLOR} AI response failed: {e}")

if __name__ == "__main__":
    main()