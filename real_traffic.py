from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import threading
import sys

def spinner(stop_event):
    spinner_chars = ['|', '/', '-', '\\']
    idx = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\rImitating real traffic... {spinner_chars[idx % len(spinner_chars)]}")
        sys.stdout.flush()
        idx += 1
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * 40 + "\r")  # Clear line

def imitate_real_traffic(target_url, count=1, wait_time=3):
    """
    Opens the target URL in a real browser window using Selenium, simulating real user visits.
    count: Number of times to open the URL.
    wait_time: Seconds to wait on the page before closing.
    """
    success = 0
    fail = 0

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_argument("--disable-logging")
    chrome_options.add_argument("--log-level=3")
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])

    stop_event = threading.Event()
    t = threading.Thread(target=spinner, args=(stop_event,))
    t.start()

    try:
        driver = webdriver.Chrome(options=chrome_options)
    except Exception:
        stop_event.set()
        t.join()
        return "Could not start browser for real traffic imitation. Please check your ChromeDriver installation."

    for _ in range(int(count)):
        try:
            driver.get(target_url)
            time.sleep(wait_time)
            success += 1
        except Exception:
            fail += 1
        time.sleep(0.2)  # Give spinner time to update

    driver.quit()
    stop_event.set()
    t.join()
    return f"Imitated real traffic: {success} successful, {fail} failed visits to {target_url}"