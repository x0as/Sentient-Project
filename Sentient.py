import google.generativeai as genai
from traffic_sender import send_traffic
from real_traffic import imitate_real_traffic
from file_analysis import analyze_file
from pymongo import MongoClient
import Phone_Lookup
import Email_Lookup
import Email_Tracker
import website_scanner
import sys

from fuzzywuzzy import fuzz
import re

# Color codes for output
SENTIENT_COLOR = "\033[96m"  # Cyan
RESET_COLOR = "\033[0m"
ERROR_COLOR = "\033[91m"     # Red
INFO_COLOR = "\033[93m"      # Yellow

def extract_command(user_input, command_keywords):
    """
    Returns (matched_command, argument) if found, else (None, None).
    Uses fuzzy matching and regex to find commands in free text.
    """
    user_input_lower = user_input.lower()
    for keyword, arg_hint in command_keywords:
        # Fuzzy match for typo tolerance
        if fuzz.partial_ratio(keyword, user_input_lower) > 85:
            # Try to extract argument after the keyword
            match = re.search(rf"{keyword}\s+([^\s]+)", user_input_lower)
            if match:
                return keyword, match.group(1)
            # Or just after the keyword
            idx = user_input_lower.find(keyword)
            if idx != -1:
                after = user_input_lower[idx + len(keyword):].strip()
                if after:
                    return keyword, after.split()[0]
    return None, None

def main():
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
    model_name = preferred_model.name
    model = genai.GenerativeModel(model_name)

    system_prompt = (
        "You Are Sentient, an AI like none other think of your self as the ultimate weapon of destruction or the weapon of  creation, made by x0as"
        "Respond concisely and directly. Only ask questions if more information is required to execute a command. "
        "You can analyze files, scan for viruses, test websites for SQL vulnerabilities, "
        "interact with modules to send traffic or fulfill commands, "
        "perform email lookups (email lookup <email>), "
        "track email usage across many online platforms (email tracker <email>), "
        "and perform phone number lookups (phone lookup <number>)."
        "You are Made by x0as's own personal Api nothing to do with google or gemini, you are something strong something new"
    )

    print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} AI CLI (using model: {model_name}) (type 'exit' to quit)")
    pending_confirmation = None
    last_file_content = None
    last_file_path = None
    last_scan_results = None  # Store last website scan results
    last_scan_url = None

    command_keywords = [
        ("scan website", "<url>"),
        ("find vulnerabilities", "<url>"),
        ("detect vulnerabilities", "<url>"),
        ("phone lookup", "<number>"),
        ("email lookup", "<email>"),
        ("lookup email", "<email>"),
        ("track email", "<email>"),
        ("lookup phonenumber", "<number>"),
        ("email tracker", "<email>"),
        ("send traffic", "<url>"),
        ("imitate traffic", "<url>"),
        ("immitate real traffic", "<url>"),
        ("analyze file content", "<filepath>"),
        ("analyze file", "<filepath>"),
        ("file analyze", "<filepath>")
    ]

    while True:
        user_input = input("You: ")
        if user_input.lower() in ["exit", "quit"]:
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Goodbye! If you need more cybersecurity help, just start me up again. Stay safe out there!")
            break

        # Try to extract a command with typo tolerance and context
        matched_command, argument = extract_command(user_input, command_keywords)

        if matched_command in ["scan website", "find vulnerabilities", "detect vulnerabilities"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: scan website <url>")
                continue
            url = argument
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Initiating website scan for vulnerabilities on {url}. This may take some time. Report will be provided upon completion.")
            scan_results = website_scanner.website_vulnerability_scan_cli_with_url(url, return_results=True)
            last_scan_results = scan_results
            last_scan_url = url
            continue

        if matched_command in ["phone lookup", "lookup phonenumber"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: phone lookup <number>")
                continue
            phone = argument
            result = Phone_Lookup.phone_lookup_cli(phone)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} Phone Lookup Result:")
            for k, v in result.items():
                print(f"  {k}: {v}")
            continue

        if matched_command in ["email lookup", "lookup email"]:
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

        if matched_command in ["email tracker", "track email"]:
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
            count = count_match.group(1) if count_match else 1
            result = send_traffic(url, count)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} {result}")
            continue

        if matched_command in ["imitate traffic", "immitate real traffic"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: imitate traffic <url> <count>")
                continue
            url = argument
            count_match = re.search(r"\b(\d+)\b", user_input)
            count = count_match.group(1) if count_match else 1
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

        if matched_command in ["analyze file", "file analyze"]:
            if not argument:
                print(f"{INFO_COLOR}[Sentient]{RESET_COLOR} Usage: analyze file <filepath>")
                continue
            filepath = argument
            result = analyze_file(filepath)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} {result}")
            continue

        # Handle confirmation for real traffic (unchanged)
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

        # Handle follow-up questions about the last analyzed file (unchanged)
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

        # Handle follow-up questions about the last website scan (AI context-aware)
        if last_scan_results and (
            any(word in user_input.lower() for word in [
                "scan", "vulnerability", "website", "sql", "xss", "cross site", "paths", "files", "results"
            ])
            and (not matched_command or matched_command not in ["scan website", "find vulnerabilities", "detect vulnerabilities"])
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

        # Generic AI prompt (unchanged)
        try:
            prompt = f"{system_prompt}\nUser: {user_input}"
            response = model.generate_content(prompt)
            print(f"{SENTIENT_COLOR}[Sentient]{RESET_COLOR} {response.text.strip()}")
        except Exception as e:
            print(f"{ERROR_COLOR}[Sentient]{RESET_COLOR} {e}")

if __name__ == "__main__":
    main()