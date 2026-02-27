import time
import joblib
import pandas as pd
import numpy as np
from fastapi import FastAPI, Request, HTTPException, Depends, status
from pydantic import BaseModel
from tensorflow.keras.models import load_model
import re

app = FastAPI(title="ML-Powered API Gateway")

# --- 1. LOAD ALL MODELS & SCALERS ---
# DDoS
ddos_model = joblib.load('DDoS/ddos_rf_model.joblib')
ddos_scaler = joblib.load('DDoS/ddos_scaler.joblib')

# Injection
inj_model = joblib.load('Injection Attack (SQLi,XSS)/injection_rf_model.joblib')
inj_scaler = joblib.load('Injection Attack (SQLi,XSS)/injection_scaler.joblib')

# Brute Force
bf_model = joblib.load('Brute Force & Credential Stuffing/bruteforce_mlp_model.joblib')
bf_scaler = joblib.load('Brute Force & Credential Stuffing/bruteforce_scaler.joblib')

inj_tfidf = joblib.load('Injection Attack (SQLi,XSS)/injection_tfidf.joblib')

# BOLA
bola_model = load_model('BOLA/bola_transformer.keras')
bola_scaler = joblib.load('BOLA/bola_scaler.joblib')

# --- 2. NON-ML UTILITIES ---

# Simple Data Masking (PII Protection)
def mask_sensitive_data(data: dict):
    # Mask emails or credit cards in response
    str_data = str(data)
    masked = re.sub(r'[\w\.-]+@[\w\.-]+', '****@****.com', str_data)
    return masked

# Rate Limiting Logic (Simplified In-Memory)
rate_limit_store = {}
def check_rate_limit(client_ip: str):
    now = time.time()
    if client_ip not in rate_limit_store:
        rate_limit_store[client_ip] = []
    
    # Keep only requests from last 60 seconds
    rate_limit_store[client_ip] = [t for t in rate_limit_store[client_ip] if now - t < 60]
    
    if len(rate_limit_store[client_ip]) > 100: # Limit to 100 req/min
        raise HTTPException(status_code=429, detail="Too Many Requests")
    
    rate_limit_store[client_ip].append(now)

# --- 3. ML FEATURE EXTRACTION (Mock for Gateway Logic) ---
# In production, you'd extract these from the live TCP flow or Request logs
def extract_flow_features(request: Request):
    # This is a placeholder for the 78 features expected by CIC-IDS models
    # In a real gateway, you use a library like 'nprint' or 'scapy'
    return np.zeros(78) 

user_behavior_history = {} 

# 3. Define the Helper Function
def extract_bola_features(client_ip: str, requested_path: str):
    now = time.time()
    if client_ip not in user_behavior_history:
        user_behavior_history[client_ip] = {"paths": set(), "last_req": now}
    
    history = user_behavior_history[client_ip]
    duration = now - history["last_req"]
    history["paths"].add(requested_path)
    
    uniqueness = len(history["paths"]) / 5.0 
    seq_length = len(history["paths"])
    history["last_req"] = now
    
    # We use a DataFrame to avoid the "Feature Names" warning you saw earlier
    data = {
        'inter_api_access_duration(sec)': [duration],
        'api_access_uniqueness': [uniqueness],
        'sequence_length(count)': [seq_length],
        'vsession_duration(min)': [0],
        'ip_type': [0],
        'num_sessions': [1],
        'num_users': [1],
        'num_unique_apis': [seq_length],
        'source': [0]
    }
    return pd.DataFrame(data)

# --- 4. THE SECURITY MIDDLEWARE ---

@app.middleware("http")
async def security_layer(request: Request, call_next):
    client_ip = request.client.host
    path = request.url.path

    try:    
        # A. Rate Limiting (Non-ML)
        check_rate_limit(client_ip)
        
        # B. DDoS Detection (ML)
        flow_features = ddos_scaler.transform([extract_flow_features(request)])
        if ddos_model.predict(flow_features)[0] == 1:
            raise HTTPException(status_code=403, detail="DDoS Attack Detected")

        # C. Injection Detection (ML)
            # Combine query params and path to check for SQLi/XSS
        payload = f"{path} {str(request.query_params)}"
        if payload.strip():
            # Vectorize the text payload
            payload_tfidf = inj_tfidf.transform([payload])
            # Predict using the Injection Random Forest model
            if inj_model.predict(payload_tfidf)[0] == 1:
                return JSONResponse(status_code=403, content={"detail": "ML-Block: Injection Attack Detected"})
        
        # D. BOLA / Anomaly Detection (ML)
        bola_raw_features = extract_bola_features(client_ip, path)
        bola_scaled = bola_scaler.transform([bola_raw_features])
        is_anomaly = bola_model.predict(bola_scaled, verbose=0)[0][0]
        
        if is_anomaly > 0.8: # Adjust threshold based on your BOLA model accuracy
            return JSONResponse(status_code=403, content={"detail": "ML-Block: BOLA/Anomalous Behavior"})
    
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": f"Gateway Error: {str(e)}"})

    return await call_next(request)
    
    # E. Security Headers (Non-ML)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    return response

# --- 5. EXAMPLE PROTECTED ENDPOINT ---

class UserProfile(BaseModel):
    user_id: int
    name: str

@app.get("/api/v1/user/{user_id}")
async def get_user(user_id: int):
    # This represents your backend optimizer/service
    return {"user_id": user_id, "name": "John Doe", "email": "john@example.com"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)