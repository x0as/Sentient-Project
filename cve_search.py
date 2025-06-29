import requests

def search_cve(product):
    url = f"https://cve.circl.lu/api/search/{product}"
    try:
        resp = requests.get(url, timeout=10)
        return resp.json()
    except Exception as e:
        return {"error": str(e)}
    
    # Example usage:
    # print(search_cve("apache"))