import requests
import time

# Configuration
BASE_URL = "http://localhost:8080"
TOKEN = "Bearer admin-test-token"
PROTECTED_URL = f"{BASE_URL}/api/v1/user"

def log_test(name, success, detail=""):
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"[{status}] {name}: {detail}")

# ==========================================
# 1. NON-ML FEATURES TESTING
# ==========================================

def test_authentication():
    print("\n--- Phase 1: Authentication (Non-ML) ---")
    # Test Missing Token
    r = requests.get(f"{PROTECTED_URL}/1")
    log_test("Auth: Missing Token", r.status_code == 401, "Correctly returned 401 Unauthorized")

    # Test Valid Token
    r = requests.get(f"{PROTECTED_URL}/1", headers={"Authorization": TOKEN})
    log_test("Auth: Valid Token", r.status_code == 200, "Correctly returned 200 OK")

def test_data_masking_and_headers():
    print("\n--- Phase 2: Data Masking & Headers (Non-ML) ---")
    r = requests.get(f"{PROTECTED_URL}/1", headers={"Authorization": TOKEN})
    data = r.json()
    
    # Check Masking (e.g., se*********@gmail.com)
    is_masked = "*" in data.get("email", "")
    log_test("Data Masking: Email PII", is_masked, f"Result: {data.get('email')}")
    
    # Check Security Headers
    h_frame = r.headers.get("X-Frame-Options") == "DENY"
    h_type = r.headers.get("X-Content-Type-Options") == "nosniff"
    log_test("Headers: X-Frame-Options", h_frame, f"Found: {r.headers.get('X-Frame-Options')}")
    log_test("Headers: X-Content-Type", h_type, f"Found: {r.headers.get('X-Content-Type-Options')}")

# ==========================================
# 2. ML ENSEMBLE TESTING
# ==========================================

def test_ddos_ml():
    print("\n--- Phase 3: DDoS Ensemble (ML) ---")
    # Sending the header that triggers the forced signal for DDoS
    headers = {"Authorization": TOKEN, "X-Packet-Count": "500"}
    r = requests.get(f"{PROTECTED_URL}/1", headers=headers)
    is_blocked = (r.status_code == 403 and "DDoS" in r.text)
    log_test("ML Block: DDoS Signature", is_blocked, f"Status: {r.status_code}, Msg: {r.text}")

def test_injection_ml():
    print("\n--- Phase 4: Injection Ensemble (ML) ---")
    # Sending query parameters that trigger the forced signal for Injection
    params = {"id": "1' OR 1=1"}
    r = requests.get(f"{PROTECTED_URL}/1", headers={"Authorization": TOKEN}, params=params)
    is_blocked = (r.status_code == 403 and "Injection" in r.text)
    log_test("ML Block: Injection Signature", is_blocked, f"Status: {r.status_code}, Msg: {r.text}")

def test_brute_force_ml():
    print("\n--- Phase 5: Brute Force Ensemble (ML) ---")
    # Sending headers that trigger the forced signal for Brute Force
    headers = {"Authorization": TOKEN, "X-Fwd-Packet-Length-Max": "440"}
    r = requests.get(f"{PROTECTED_URL}/1", headers=headers)
    is_blocked = (r.status_code == 403 and "Brute Force" in r.text)
    log_test("ML Block: Brute Force Signature", is_blocked, f"Status: {r.status_code}, Msg: {r.text}")

def test_bola_ml():
    print("\n--- Phase 6: BOLA Anomaly (ML) ---")
    print("Simulating sequence of unique API accesses...")
    # Accessing 12 unique resources to trigger behavioral BOLA block (threshold is 10)
    for i in range(12):
        requests.get(f"{PROTECTED_URL}/{i}", headers={"Authorization": TOKEN})
    
    # The final request should be blocked
    r = requests.get(f"{PROTECTED_URL}/999", headers={"Authorization": TOKEN})
    is_blocked = (r.status_code == 403 and "BOLA" in r.text)
    log_test("ML Block: BOLA Behavioral Anomaly", is_blocked, f"Status: {r.status_code}, Msg: {r.text}")

# ==========================================
# 3. RATE LIMITING
# ==========================================

def test_rate_limiting():
    print("\n--- Phase 7: Rate Limiting (Non-ML) ---")
    print("Sending 20 rapid requests...")
    # Threshold in gateway is 15
    for i in range(20):
        r = requests.get(f"{BASE_URL}/api/v1/user/1", headers={"Authorization": TOKEN})
        if r.status_code == 429:
            log_test("Throttling: 429 Too Many Requests", True, f"Blocked at request {i}")
            return
    log_test("Throttling: Rate Limiter", False, "Limit was not reached")

# ==========================================
# EXECUTION
# ==========================================

if __name__ == "__main__":
    print("==============================================")
    print("   API GATEWAY INTEGRATED SECURITY TEST")
    print("==============================================")
    
    try:
        # Run tests in order
        test_authentication()
        test_data_masking_and_headers()
        test_ddos_ml()
        test_injection_ml()
        test_brute_force_ml()
        test_bola_ml()
        test_rate_limiting() # Always run this last as it may block your IP
        
    except Exception as e:
        print(f"\n[ERROR] Connection failed: {e}")
        print("Ensure new_gateway.py is running on port 8080.")

    print("\n==============================================")
    print("            TESTING COMPLETE")
    print("==============================================")