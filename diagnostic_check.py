import time, joblib, re, numpy as np, pandas as pd
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from tensorflow.keras.models import load_model
import xgboost as xgb

app = FastAPI()

# --- GLOBALS ---
rate_limit_store = {}
user_behavior_history = {}

# --- LOAD MODELS ---
# ==========================================
# 1. LOAD ALL MODELS (The Full Arsenal)
# ==========================================

# --- INJECTION MODELS ---
inj_svm = joblib.load('Injection Attack (SQLi,XSS)/injection_svm_model.joblib')
inj_rf = joblib.load('Injection Attack (SQLi,XSS)/injection_rf_model.joblib')
inj_cnn_lstm = load_model('Injection Attack (SQLi,XSS)/injection_hybrid_model.keras')
inj_scaler = joblib.load('Injection Attack (SQLi,XSS)/injection_scaler.joblib')

# --- DDoS MODELS ---
ddos_rf = joblib.load('DDoS/ddos_rf_model.joblib')
ddos_dt = joblib.load('DDoS/ddos_dt_model.joblib')
ddos_xgb = xgb.XGBClassifier()
ddos_xgb.load_model('DDoS/ddos_xgboost_model.json')
ddos_lstm = load_model('DDoS/ddos_lstm_model.keras')
ddos_scaler = joblib.load('DDoS/ddos_scaler.joblib')

# --- BOLA MODELS ---
bola_iso = joblib.load('BOLA/bola_iso_forest.joblib')
bola_ae = load_model('BOLA/bola_autoencoder.keras')
bola_trans = load_model('BOLA/bola_transformer.keras')
bola_scaler = joblib.load('BOLA/bola_scaler.joblib')

# --- BRUTE FORCE MODELS ---
bf_kmeans = joblib.load('Brute Force & Credential Stuffing/bruteforce_kmeans_model.joblib')
bf_mlp = joblib.load('Brute Force & Credential Stuffing/bruteforce_mlp_model.joblib')
bf_scaler = joblib.load('Brute Force & Credential Stuffing/bruteforce_scaler.joblib')

# (Assume models are loaded as ddos_rf, ddos_scaler, etc.)

def diagnostic_check(model_name, model, scaled_data):
    """Prints the model's inner thoughts to the console."""
    prediction = model.predict(scaled_data)
    # Handle both Keras (proba) and Sklearn (classes)
    val = prediction[0][0] if isinstance(prediction[0], (np.ndarray, list)) else prediction[0]
    print(f"[DEBUG] {model_name} Prediction: {val}")
    return val

def get_network_flow_features(request: Request, scaler):
    """Creates a DataFrame with EXACT column names to match training."""
    cols = scaler.feature_names_in_
    df = pd.DataFrame(np.zeros((1, len(cols))), columns=cols)
    
    # Fill based on common CIC-IDS features
    if "X-Packet-Count" in request.headers:
        # We use 'middle-range' values that actually look like attacks
        if 'Total Fwd Packets' in cols: df['Total Fwd Packets'] = 500
        if 'Flow Duration' in cols: df['Flow Duration'] = 50000
    
    if "X-Fwd-Packet-Length-Max" in request.headers:
        if 'Fwd Packet Length Max' in cols: df['Fwd Packet Length Max'] = 1000
        
    if len(str(request.query_params)) > 10:
        if 'Fwd Packet Length Max' in cols: df['Fwd Packet Length Max'] = 1500

    if 'Unnamed: 0' in cols: df['Unnamed: 0'] = 0
    return df

@app.middleware("http")
async def security_gateway_engine(request: Request, call_next):
    client_ip = request.client.host
    path = request.url.path
    print(f"\n>>> Incoming Request from {client_ip} to {path}")

    try:
        # 1. Rate Limiting (Fixed Logic)
        now = time.time()
        if client_ip not in rate_limit_store: rate_limit_store[client_ip] = []
        rate_limit_store[client_ip] = [t for t in rate_limit_store[client_ip] if now - t < 60]
        print(f"[DEBUG] Rate Limit Count: {len(rate_limit_store[client_ip])}")
        
        # Lowered to 5 for immediate testing
        if len(rate_limit_store[client_ip]) > 5: 
            print("!!! RATE LIMIT TRIGGERED !!!")
            return JSONResponse(status_code=429, content={"detail": "Throttled"})
        rate_limit_store[client_ip].append(now)

        # 2. ML DDoS Check
        ddos_df = get_network_flow_features(request, ddos_scaler)
        ddos_scaled = ddos_scaler.transform(ddos_df)
        if diagnostic_check("DDoS RF", ddos_rf, ddos_scaled) == 1:
            return JSONResponse(status_code=403, content={"detail": "ML-Block: DDoS"})

        # 3. ML Injection Check
        inj_df = get_network_flow_features(request, inj_scaler)
        inj_scaled = inj_scaler.transform(inj_df)
        if diagnostic_check("Injection RF", inj_rf, inj_scaled) == 1:
            return JSONResponse(status_code=403, content={"detail": "ML-Block: Injection"})

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return JSONResponse(status_code=500, content={"detail": f"Error: {str(e)}"})

    return await call_next(request)

# ... (Endpoints and Auth logic) ...