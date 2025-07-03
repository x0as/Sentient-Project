import requests

def dir_bruteforce(url, wordlist=None):
    if wordlist is None:
        wordlist = ["admin", "login", "dashboard", "uploads",]
    found = []
    for words in wordlist:
        test_url = url.rstrip("/") + "/" + words
        try:
            resp = requests.get(test_url, timeout=3)
            if resp.status_code == 200:
                found.append(test_url)
        except Exception:
            continue
    return found