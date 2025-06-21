import dns.resolver
import re

def get_email_info(email):
    info = {}
    try:
        domain_all = email.split('@')[-1]
    except:
        domain_all = None

    try:
        name = email.split('@')[0]
    except:
        name = None

    try:
        domain = re.search(r"@([^@.]+)\.", email).group(1)
    except:
        domain = None
    try:
        tld = f".{email.split('.')[-1]}"
    except:
        tld = None

    try:
        mx_records = dns.resolver.resolve(domain_all, 'MX')
        mx_servers = [str(record.exchange) for record in mx_records]
        info["mx_servers"] = mx_servers
    except Exception:
        info["mx_servers"] = None

    try:
        spf_records = dns.resolver.resolve(domain_all, 'SPF')
        info["spf_records"] = [str(record) for record in spf_records]
    except Exception:
        info["spf_records"] = None

    try:
        dmarc_records = dns.resolver.resolve(f'_dmarc.{domain_all}', 'TXT')
        info["dmarc_records"] = [str(record) for record in dmarc_records]
    except Exception:
        info["dmarc_records"] = None

    if info.get("mx_servers"):
        for server in info["mx_servers"]:
            if "google.com" in server:
                info["google_workspace"] = True
            elif "outlook.com" in server:
                info["microsoft_365"] = True

    return {
        "Email": email,
        "Name": name,
        "Domain": domain,
        "Tld": tld,
        "Domain All": domain_all,
        "Servers": info.get("mx_servers"),
        "Spf": info.get("spf_records"),
        "Dmarc": info.get("dmarc_records"),
        "Workspace": info.get("google_workspace"),
        "Mailgun": info.get("mailgun_validation") if "mailgun_validation" in info else None,
    }

def email_lookup_cli(email):
    result = get_email_info(email)
    return result