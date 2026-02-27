import requests
import time
import json

BASE_URL = "http://localhost:8080"
ADMIN_TOKEN = "Bearer admin-token"
USER_TOKEN = "Bearer user-token"

def log_test(name, result, detail=""):
    status = "✅ PASS" if result else "❌ FAIL"
    print(f"[{status}] {name}: {detail}")

# --- 1. Testing Non-ML Security Features ---
def test_protocol_headers():
    print("\n--- Phase 2: Security Headers ---")
    r = requests.get(f"{BASE_URL}/api/v1/user/1", headers={"Authorization": "Bearer admin"})
    # Check if header exists in the response
    header = r.headers.get("X-Frame-Options")
    log_test("Protocol: Security Headers", header == "DENY", f"Found: {header}")


def test_authentication():
    print("\n--- Phase 1: Authentication & RBAC ---")
    # No Token
    r = requests.get(f"{BASE_URL}/api/v1/user/1")
    log_test("Auth: Missing Token", r.status_code == 401, "Correctly returned 401")

    # Valid Admin Token
    r = requests.get(f"{BASE_URL}/api/v1/user/1", headers={"Authorization": ADMIN_TOKEN})
    log_test("Auth: Valid Admin", r.status_code == 200, "Access granted")

    # RBAC: User accessing Admin resource
    # (Assuming our logic treats high user_ids or specific endpoints as admin-only)
    r = requests.get(f"{BASE_URL}/api/v1/user/1", headers={"Authorization": USER_TOKEN})
    # Our Gateway check_rbac logic: if 'admin' not in token, block.
    log_test("RBAC: Block User from Admin", r.status_code == 403, "Correctly restricted user role")

def test_data_masking():
    print("\n--- Phase 2: Data Masking & Headers ---")
    r = requests.get(f"{BASE_URL}/api/v1/user/1", headers={"Authorization": ADMIN_TOKEN})
    data = r.json()
    email_masked = "*" in data.get("email", "")
    log_test("Data Masking: Email Sanitization", email_masked, f"Result: {data.get('email')}")
    
    header_check = r.headers.get("X-Frame-Options") == "DENY"
    log_test("Protocol: Security Headers", header_check, "X-Frame-Options: DENY found")

def test_rate_limiting():
    print("\n--- Phase 3: Rate Limiting ---")
    # We hit it 10 times (threshold is 5)
    for i in range(10):
        r = requests.get(f"{BASE_URL}/api/v1/user/1", headers={"Authorization": ADMIN_TOKEN})
        print(f"Req {i}: Status {r.status_code}")
        if r.status_code == 429:
            print("✅ Rate Limiter Triggered!")
            return
    print("❌ Rate Limiter Failed")

# --- 2. Testing ML Ensemble Layers ---

def test_ddos_ensemble():
    print("\n--- Phase 4: DDoS Ensemble Detection ---")
    # Trigger the DDoS logic in the gateway
    headers = {"Authorization": ADMIN_TOKEN, "X-Packet-Count": "500"}
    r = requests.get(f"{BASE_URL}/api/v1/user/1", headers=headers)
    
    is_blocked = (r.status_code == 403 and "DDoS" in r.text)
    log_test("ML Ensemble: DDoS Pattern", is_blocked, f"Status: {r.status_code}")

def test_bola_anomaly():
    print("\n--- Phase 5: BOLA Ensemble Detection ---")
    # Simulate an attacker scraping IDs
    for i in range(12):
        requests.get(f"{BASE_URL}/api/v1/user/{i}", headers={"Authorization": "Bearer admin"})
    
    r = requests.get(f"{BASE_URL}/api/v1/user/999", headers={"Authorization": "Bearer admin"})
    is_blocked = (r.status_code == 403 and "BOLA" in r.text)
    log_test("ML Ensemble: BOLA Anomaly", is_blocked, f"Status: {r.status_code}")

def test_injection_ensemble():
    print("\n--- Phase 6: Injection Ensemble Detection ---")
    # Trigger the Injection logic in the gateway using query params
    params = {"id": "1' OR 1=1"}
    r = requests.get(f"{BASE_URL}/api/v1/user/1", headers={"Authorization": ADMIN_TOKEN}, params=params)
    
    is_blocked = (r.status_code == 403 and "Injection" in r.text)
    log_test("ML Ensemble: Web Injection Pattern", is_blocked, f"Status: {r.status_code}")

def test_brute_force_signature():
    print("\n--- Testing Brute Force ML Signature ---")
    headers = {
        "Authorization": ADMIN_TOKEN, # Add token so we don't get a 401
        "X-Fwd-Packet-Length-Max": "440" 
    }
    # Hit the user endpoint with a brute force tool signature
    r = requests.get(f"{BASE_URL}/api/v1/user/1", headers=headers)
    
    if r.status_code == 403 and "Brute Force" in r.text:
        print("✅ Success: MLP Ensemble identified the pattern.")
    else:
        print(f"❌ Failed: Status {r.status_code}, Msg: {r.text}")
    
def test_credential_stuffing_behavior():
    print("\n--- Testing Credential Stuffing Behavior (K-Means) ---")
    # Credential stuffing involves hitting the login endpoint with many variations
    print("Simulating 20 rapid login attempts...")
    
    for i in range(20):
        data = {"username": f"user_{i}", "password": "password"}
        response = requests.post(f"{BASE_URL}/api/v1/user/login", json=data)
        
        # We check if the gateway starts blocking based on behavior
        if response.status_code == 403:
            print(f"✅ Success: K-Means clustered this as 'Attack' behavior at attempt {i}")
            return
        elif response.status_code == 429:
            print(f"✅ Success: Non-ML Rate Limiter blocked the attack at attempt {i}")
            return

    print("❌ Failed: Attacker was able to complete all attempts.")

if __name__ == "__main__":
    print("==============================================")
    print("STARTING API GATEWAY SECURITY PEN-TEST")
    print("==============================================")
    
    try:
        # 1. TEST ML FIRST (while rate limit is fresh)
        test_ddos_ensemble()
        test_injection_ensemble()
        test_bola_ensemble()
        
        # 2. TEST AUTH & MASKING
        test_authentication()
        test_data_masking()
        
        # 3. TEST RATE LIMIT LAST
        test_rate_limiting()    
    except Exception as e:
        print(f"Test Suite Error: {e}")
    
    print("\n==============================================")
    print("TESTING COMPLETE")
    print("==============================================")