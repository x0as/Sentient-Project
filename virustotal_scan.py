import requests

def scan_url_virustotal(url, api_key):
    vt_url = "https://www.virustotal.com/api/v3/urls"
    try:
        resp = requests.post(vt_url, headers={"x-apikey": api_key}, data={"url": url})
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

# Example usage:
# print(scan_url_virustotal("http://example.com", "YOUR_VT_API_KEY"))