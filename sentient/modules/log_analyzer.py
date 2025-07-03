import re

def analyze_log(filepath):
    suspicious_patterns = [
        r"Failed password",
        r"authentication failure",
        r"invalid user",
        r"error",
        r"unauthorized",
        r"root login",
        r"sqlmap",
        r"nmap",
        r"hydra",
        r"brute",
        r"malware",
        r"exploit"
    ]
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, 1):
                for pat in suspicious_patterns:
                    if re.search(pat, line, re.IGNORECASE):
                        findings.append(f"Line {i}: {line.strip()}")
        return findings if findings else ["No suspicious activity found."]
    except Exception as e:
        return [f"Error: {e}"]