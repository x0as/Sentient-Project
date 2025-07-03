import requests

def subdomain_enum_cli(domain):
    # Simple brute-force with a small wordlist for demo
    subdomains = ["www", "mail", "ftp", "test", "dev", "api", "blog", "shop", "staging"]
    found = []
    for sub in subdomains:
        url = f"http://{sub}.{domain}"
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code < 400:
                found.append(url)
        except Exception:
            continue
    return found