import requests

def reverse_ip_lookup(ip):
    try:
        resp = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=10)
        if resp.status_code == 200:
            return resp.text.splitlines()
        else:
            return {"error": f"Status {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# Example usage:
# print(reverse_ip_lookup("8.8.8.8"))