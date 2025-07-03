import requests

def send_traffic(target_url, count=1):
    """
    Sends a number of HTTP GET requests to the target URL.
    Returns a summary string.
    """
    success = 0
    fail = 0
    for _ in range(int(count)):
        try:
            response = requests.get(target_url, timeout=3)
            if response.status_code == 200:
                success += 1
            else:
                fail += 1
        except Exception:
            fail += 1
    return f"Traffic sent: {success} successful, {fail} failed requests to {target_url}"