import requests
import time
import numpy as np

BASE_URL = "http://127.0.0.1:8080"

def test_normal_request():
    print("\n--- Testing Normal Traffic ---")
    response = requests.get(f"{BASE_URL}/api/v1/user/1")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    print(f"Security Headers: {response.headers.get('X-Frame-Options')}")

def test_rate_limiting():
    print("\n--- Testing Rate Limiting (Non-ML) ---")
    for i in range(105):
        resp = requests.get(f"{BASE_URL}/api/v1/user/1")
        if resp.status_code == 429:
            print(f"Successfully blocked at request {i} with 429")
            break

def test_injection_attack():
    print("\n--- Testing SQL Injection Detection ---")
    # Sending a classic SQLi payload in query params
    payload = {"id": "1' OR '1'='1"}
    response = requests.get(f"{BASE_URL}/api/v1/user/1", params=payload)
    print(f"Status: {response.status_code}")
    if response.status_code == 403:
        print("✅ Injection Attack Blocked by ML Layer")

def test_bola_anomaly():
    print("\n--- Testing BOLA/Anomaly Detection ---")
    # Simulate a user scraping 20 different user profiles in 1 second
    for i in range(20):
        requests.get(f"{BASE_URL}/api/v1/user/{i}")
    
    # This should now look like an outlier to the Transformer model
    response = requests.get(f"{BASE_URL}/api/v1/user/999")
    print(f"Status: {response.status_code}")
    if response.status_code == 403:
        print("✅ BOLA Anomaly Blocked!")
    else:
        print("❌ BOLA not detected. Check model threshold.")

if __name__ == "__main__":
    # 1. Start your gateway script first (python gateway.py)
    # 2. Then run this test script
    try:
        test_normal_request()
        test_injection_attack()
        test_bola_anomaly()


        test_rate_limiting()
    except Exception as e:
        print(f"Error: {e}. Is the Gateway running?")