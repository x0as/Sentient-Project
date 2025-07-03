import requests

def expand_url(short_url):
    try:
        resp = requests.head(short_url, allow_redirects=True, timeout=10)
        return resp.url
    except Exception as e:
        return {"error": str(e)}

# Example usage:
# print(expand_url("https://bit.ly/3kTQF2C"))