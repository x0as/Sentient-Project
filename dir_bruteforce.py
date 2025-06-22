import requests

def dir_bruteforce_cli(url, wordlist=None):
    if wordlist is None:
        wordlist = ["admin", "login", "dashboard", "uploads", "images", "css", "js", "backup", "test", "old"]
    found = []
    for word in wordlist:
        test_url = url.rstrip("/") + "/" + word
        try:
            resp = requests.get(test_url, timeout=3)
            if resp.status_code == 200:
                found.append(test_url)
        except Exception:
            continue
    return found