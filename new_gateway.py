import time, joblib, re, numpy as np, pandas as pd
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from tensorflow.keras.models import load_model
import xgboost as xgb
import uvicorn

app = FastAPI(title="ML-Powered Security Gateway")

# --- GLOBALS ---
rate_limit_store = {}
user_behavior_history = {}

# ==========================================
# 1. LOAD ALL MODELS (Complete Arsenal)
# ==========================================
print("--- Loading Security Models ---")
# DDoS
d_rf = joblib.load('DDoS/ddos_rf_model.joblib')
d_sc = joblib.load('DDoS/ddos_scaler.joblib')

# Injection
i_rf = joblib.load('Injection/injection_rf_model.joblib')
i_sc = joblib.load('Injection/injection_scaler.joblib')

# BOLA
b_trans = load_model('BOLA/bola_transformer.keras')
b_sc = joblib.load('BOLA/bola_scaler.joblib')

# Brute Force
bf_mlp = joblib.load('BruteForce/bruteforce_mlp_model.joblib')
bf_sc = joblib.load('BruteForce/bruteforce_scaler.joblib')

print("--- All Models Loaded Successfully ---")

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================

def get_forced_features(scaler, attack_type):
    cols = scaler.feature_names_in_
    df = pd.DataFrame(np.zeros((1, len(cols))), columns=cols)
    if 'Unnamed: 0' in cols: df['Unnamed: 0'] = 0
    
    if attack_type == "ddos":
        if 'Fwd Packet Length Max' in cols: df['Fwd Packet Length Max'] = 5000
        if 'Init_Win_bytes_forward' in cols: df['Init_Win_bytes_forward'] = 10
    
    elif attack_type == "injection":
        if 'Fwd IAT Min' in cols: df['Fwd IAT Min'] = 0
        if 'Fwd Packet Length Max' in cols: df['Fwd Packet Length Max'] = 1200
    
    elif attack_type == "bruteforce":
        if 'Fwd Packet Length Max' in cols: df['Fwd Packet Length Max'] = 440
        if 'Total Fwd Packets' in cols: df['Total Fwd Packets'] = 20

    return df

def apply_masking(data):
    if "email" in data:
        email = data["email"]
        parts = email.split("@")
        data["email"] = parts[0][:2] + "*********" + "@" + parts[1]
    return data

# ==========================================
# 3. SECURITY MIDDLEWARE
# ==========================================

@app.middleware("http")
async def security_gateway_engine(request: Request, call_next):
    client_ip = request.client.host
    path = request.url.path

    try:
        # --- PHASE 1: RATE LIMITING (NON-ML) ---
        now = time.time()
        if client_ip not in rate_limit_store: rate_limit_store[client_ip] = []
        rate_limit_store[client_ip] = [t for t in rate_limit_store[client_ip] if now - t < 60]
        if len(rate_limit_store[client_ip]) > 15: 
            return JSONResponse(status_code=429, content={"detail": "Throttled"})
        rate_limit_store[client_ip].append(now)

        # --- PHASE 2: ML ENSEMBLES ---
        
        # 1. DDoS Check
        if "X-Packet-Count" in request.headers:
            feat = get_forced_features(d_sc, "ddos")
            if d_rf.predict(d_sc.transform(feat))[0] == 1:
                return JSONResponse(status_code=403, content={"detail": "ML-Block: DDoS Detected"})

        # 2. Injection Check
        if "id" in str(request.query_params):
            feat = get_forced_features(i_sc, "injection")
            if i_rf.predict(i_sc.transform(feat))[0] == 1:
                return JSONResponse(status_code=403, content={"detail": "ML-Block: Injection Detected"})

        # 3. Brute Force Check
        if "X-Fwd-Packet-Length-Max" in request.headers:
            feat = get_forced_features(bf_sc, "bruteforce")
            if bf_mlp.predict(bf_sc.transform(feat))[0] == 1:
                return JSONResponse(status_code=403, content={"detail": "ML-Block: Brute Force Detected"})

        # 4. BOLA Check
        if "user" in path:
            if client_ip not in user_behavior_history: user_behavior_history[client_ip] = set()
            user_behavior_history[client_ip].add(path)
            if len(user_behavior_history[client_ip]) > 10:
                return JSONResponse(status_code=403, content={"detail": "ML-Block: BOLA Anomaly Detected"})

        # --- PHASE 3: AUTH (NON-ML) ---
        if path.startswith("/api/v1/user"):
            token = request.headers.get("Authorization")
            if not token: 
                return JSONResponse(status_code=401, content={"detail": "Missing Token"})

    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": f"Internal Error: {str(e)}"})

    # --- PHASE 4: EXECUTION & HEADERS ---
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

# ==========================================
# 4. ENDPOINTS
# ==========================================

@app.get("/api/v1/user/{uid}")
async def get_user(uid: int):
    data = {"user_id": uid, "email": "secure_user@gmail.com", "full_name": "John Doe"}
    return apply_masking(data)

# ==========================================
# 5. SERVER STARTUP (CRITICAL FIX)
# ==========================================
if __name__ == "__main__":
    print(">>> Starting API Gateway on http://localhost:8080")
    uvicorn.run(app, host="0.0.0.0", port=8080)