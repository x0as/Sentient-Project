import requests

def geoip_lookup(ip):
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        return resp.json()
    except Exception as e:
        return {"error": str(e)}
    
    # Example usage:
    # print(geoip_lookup("8.8.8.8"))