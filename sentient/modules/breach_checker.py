import requests

def check_breach(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": "YOUR_API_KEY", "user-agent": "sentient-cli"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return {"result": "No breach found."}
        else:
            return {"error": f"Status {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# Example usage:
# print(check_breach("test@example.com"))