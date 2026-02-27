import time
import re
import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from tensorflow.keras.models import load_model

app = FastAPI(title="Proactive ML API Gateway")

# ==========================================
# 1. LOAD ALL ML MODELS & SCALERS
# ==========================================
print("Loading ML Security Layers...")
# DDoS (Friday Dataset)
ddos_model = joblib.load('ddos_rf_model.joblib')
ddos_scaler = joblib.load('ddos_scaler.joblib')

# Brute Force (Tuesday Dataset)
bf_model = joblib.load('bruteforce_mlp_model.joblib')
bf_scaler = joblib.load('bruteforce_scaler.joblib')

# Injection (Thursday PCAP-based Model - No TF-IDF)
inj_model = joblib.load('injection_rf_model.joblib')
inj_scaler = joblib.load('injection_scaler.joblib')

# BOLA (Behavioral Model)
bola_model = load_model('bola_transformer.keras')
bola_scaler = joblib.load('bola_scaler.joblib')

# Global state for BOLA behavior tracking
user_behavior_history = {}

# ==========================================
# 2. NON-ML FEATURES & UTILITIES
# ==========================================

# A. Authentication & RBAC (Non-ML)
# Simulated JWT Role-Based Access Control
def verify_auth(request: Request):
    token = request.headers.get("Authorization")
    if not token or "Bearer " not in token:
        raise HTTPException(status_code=401, detail="Unauthorized: Missing Token")
    # In a real app, decode JWT. Here we mock roles:
    role = "admin" if "admin-token" in token else "user"
    return {"user": "test_user", "role": role}

# B. Rate Limiting (Non-ML)
rate_limit_store = {}
def check_rate_limit(client_ip: str):
    now = time.time()
    rate_limit_store[client_ip] = [t for t in rate_limit_store.get(client_ip, []) if now - t < 60]
    if len(rate_limit_store[client_ip]) > 50: # Limit: 50 req/min
        raise HTTPException(status_code=429, detail="Rate Limit Exceeded")
    rate_limit_store[client_ip].append(now)

# C. Data Masking (Non-ML Output Sanitization)
def mask_sensitive_data(response_dict: dict):
    # Masking Email patterns in the output
    if "email" in response_dict:
        response_dict["email"] = re.sub(r'(?<=.{2}).(?=[^@]*?@)', '*', response_dict["email"])
    return response_dict

# D. Feature Extraction for ML
def get_network_flow_features(request: Request):
    # Mapping request metadata to 78 features for DDoS/BF/Injection
    # Index 0: Content Length, Index 1: Header Count, etc.
    features = np.zeros(78)
    features[0] = int(request.headers.get("content-length", 0))
    features[1] = len(request.headers)
    return features.reshape(1, -1)

def get_bola_features(client_ip: str, path: str):
    now = time.time()
    if client_ip not in user_behavior_history:
        user_behavior_history[client_ip] = {"paths": set(), "last_req": now}
    history = user_behavior_history[client_ip]
    duration = now - history["last_req"]
    history["paths"].add(path)
    # Match the 9 features of remaing_behaviour_ext.csv
    data = {
        'inter_api_access_duration(sec)': [duration],
        'api_access_uniqueness': [len(history["paths"]) / 5.0],
        'sequence_length(count)': [len(history["paths"])],
        'vsession_duration(min)': [0], 'ip_type': [0],
        'num_sessions': [1], 'num_users': [1],
        'num_unique_apis': [len(history["paths"])], 'source': [0]
    }
    history["last_req"] = now
    return pd.DataFrame(data)

# ==========================================
# 3. THE INTEGRATED SECURITY MIDDLEWARE
# ==========================================

@app.middleware("http")
async def gateway_security_engine(request: Request, call_next):
    client_ip = request.client.host
    path = request.url.path

    try:
        # --- PHASE 1: NON-ML PRE-CHECKS ---
        check_rate_limit(client_ip)

        # --- PHASE 2: NETWORK ML MODELS (DDoS, BF, INJECTION) ---
        raw_flow = get_network_flow_features(request)
        
        # 1. DDoS Check
        if ddos_model.predict(ddos_scaler.transform(raw_flow))[0] == 1:
            return JSONResponse(status_code=403, content={"detail": "Security Block: DDoS Detected"})

        # 2. Brute Force Check
        if bf_model.predict(bf_scaler.transform(raw_flow))[0] == 1:
            return JSONResponse(status_code=403, content={"detail": "Security Block: Brute Force Detected"})

        # 3. Injection Check (PCAP Signature Based)
        if inj_model.predict(inj_scaler.transform(raw_flow))[0] == 1:
            return JSONResponse(status_code=403, content={"detail": "Security Block: Injection Pattern Detected"})

        # --- PHASE 3: BEHAVIORAL ML MODEL (BOLA) ---
        bola_df = get_bola_features(client_ip, path)
        bola_scaled = bola_scaler.transform(bola_df)
        is_bola = bola_model.predict(bola_scaled, verbose=0)[0][0]
        if is_bola > 0.8: # Anomaly Threshold
            return JSONResponse(status_code=403, content={"detail": "Security Block: BOLA Anomaly Detected"})

    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": f"Gateway Error: {str(e)}"})

    # --- PHASE 4: API EXECUTION ---
    response = await call_next(request)

    # --- PHASE 5: POST-PROCESSING (Headers & Masking) ---
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

# ==========================================
# 4. PROTECTED API ENDPOINTS (Schema Validation)
# ==========================================

class UserUpdate(BaseModel):
    # Non-ML Schema Validation Feature
    name: str
    email: EmailStr
    age: int

@app.get("/api/v1/resource/{item_id}")
async def get_resource(item_id: int, auth: dict = Depends(verify_auth)):
    # Authorization (RBAC)
    if auth['role'] != "admin" and item_id > 100:
        raise HTTPException(status_code=403, detail="RBAC: Access Denied to this Resource")
    
    data = {"item_id": item_id, "owner": "admin", "email": "admin@company.com"}
    # Data Masking
    return mask_sensitive_data(data)

@app.post("/api/v1/user/update")
async def update_user(data: UserUpdate):
    return {"status": "success", "updated_user": data.name}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)