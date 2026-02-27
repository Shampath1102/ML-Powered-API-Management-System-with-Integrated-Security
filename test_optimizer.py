import requests
import time

BASE_URL = "http://127.0.0.1:8000"

def test_feature(name, method, endpoint, headers=None):
    print(f"\n--- Testing: {name} ---")
    start = time.time()
    response = requests.request(method, f"{BASE_URL}{endpoint}", headers=headers)
    duration = (time.time() - start) * 1000
    print(f"Status: {response.status_code}")
    print(f"Time: {duration:.2f}ms")
    print(f"Headers: {dict(response.headers)}")
    try:
        print(f"Body: {response.json()}")
    except:
        print(f"Body: {response.text[:100]}")
    return response

# --- SCENARIO 1: Normal Traffic & Caching ---
# First call should be a MISS, second should be a HIT
test_feature("Caching (First Call)", "GET", "/optimize")
test_feature("Caching (Second Call - HIT)", "GET", "/optimize")

# --- SCENARIO 2: Shadow API Detection & Dynamic Rate Limiting ---
# We use a pattern the model should flag as an anomaly (SQL Injection or Shadow Path)
print("\n--- Testing: Shadow API Detection ---")
# This URL matches the malicious patterns found in your Cisco training output
malicious_url = "/orders/get/country?country=';SELECT%20*%20FROM%20users"
response = requests.get(f"{BASE_URL}{malicious_url}")

# Now check if Rate Limiting kicked in (Shadow APIs have stricter limits)
print("Checking if Rate Limit tightened for the suspicious IP...")
for i in range(5):
    res = requests.get(f"{BASE_URL}/optimize")
    if res.status_code == 429:
        print(f"SUCCESS: Dynamic Rate Limit blocked user after {i+1} requests.")
        break

# --- SCENARIO 3: Smart Routing ---
# Look at your server logs; it should show "target_node" selected by ML
test_feature("Smart Routing", "GET", "/optimize")

# --- SCENARIO 4: Predictive Scaling ---
# Check the NASA model's forecast
test_feature("Predictive Scaling Forecast", "GET", "/system/predict-load")

# --- SCENARIO 5: Self-Healing (Circuit Breaker) ---
print("\n--- Testing: Self-Healing (Circuit Breaker) ---")
print("Simulating 6 consecutive backend failures...")
# We assume an endpoint that fails (or we simulate it by hitting a non-existent route)
for _ in range(6):
    requests.get(f"{BASE_URL}/fail-test-route")

# The 7th call should be blocked by the Circuit Breaker WITHOUT hitting the backend
res = requests.get(f"{BASE_URL}/optimize")
if res.status_code == 503:
    print("SUCCESS: Circuit Breaker is OPEN. Service is in Self-Healing mode.")