import time
import json
import re
import redis
import joblib
import brotli_asgi
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from typing import List

app = FastAPI(title="AI-Powered API Optimizer (Integrated)")

# --- 1. LOAD ML ASSETS (Only the ones you have) ---
print("Loading validated ML models...")
# NASA: Predictive Scaling
scaling_model = joblib.load('traffic_predictor.pkl')
# Cisco: Shadow API Detection
shadow_assets = joblib.load('shadow_api_model.pkl')
# NetLatency: Smart Router
routing_assets = joblib.load('smart_routing_model.pkl')

# State Store (Redis)
r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# Performance Middleware
app.add_middleware(brotli_asgi.BrotliMiddleware, quality=4)

# --- 2. THE CORE OPTIMIZER ENGINE ---

def get_dynamic_rate_limit(client_ip: str, is_shadow: bool):
    """
    DYNAMIC RATE LIMITING: 
    Adjusts token bucket capacity based on ML-detected risk.
    """
    # If Shadow API is detected, limit is strictly 5 req/min. 
    # Otherwise, 100 req/min.
    limit = 5 if is_shadow else 100
    period = 60
    
    now = time.time()
    key = f"rl:{client_ip}"
    
    # Simple Token Bucket in Redis
    data = r.get(key)
    if data:
        tokens, last_refill = json.loads(data)
        elapsed = now - last_refill
        tokens = min(limit, tokens + elapsed * (limit / period))
    else:
        tokens = limit

    if tokens >= 1:
        r.setex(key, period, json.dumps([tokens - 1, now]))
        return True
    return False

def get_smart_route(client_node_id: int, server_nodes: List[int]):
    """SMART ROUTING: Predicts the best path using the NetLatency model."""
    best_node = server_nodes[0]
    min_latency = float('inf')
    
    for node in server_nodes:
        # Change: Remove ['model'] because routing_assets is the model itself
        pred = routing_assets.predict([[client_node_id, node]])[0] 
        if pred < min_latency:
            min_latency = pred
            best_node = node
    return best_node

def detect_shadow_api(method: str, url: str):
    """SHADOW API DETECTION: Flags undocumented patterns."""
    # 1. Normalize the URL
    path = re.sub(r'https?://[\d\.]+(:\d+)?', '', str(url))
    path = re.sub(r'/\d+', '/{id}', path)
    endpoint = f"{method} {path}"
    
    # 2. Transform into the 500-feature vector
    # (Matches the TF-IDF you exported in the latest pkl)
    vec = shadow_assets['vectorizer'].transform([endpoint])
    
    # 3. Predict directly using the Isolation Forest model
    # We use 'vec' directly because there is no 'svd' layer anymore
    is_anomaly = shadow_assets['model'].predict(vec)[0]
    
    return True if is_anomaly == -1 else False

# --- 3. THE MIDDLEWARE PIPELINE ---
    
@app.middleware("http")
async def optimizer_pipeline(request: Request, call_next):
    client_ip = request.client.host
    
    # 1. SHADOW API DETECTION (ML)
    is_shadow = detect_shadow_api(request.method, request.url)
    if is_shadow:
        r.incr("stats:shadow_detections")

    # 2. DYNAMIC RATE LIMITING (Context-Aware)
    # Automatically punishes shadow API probes with 95% lower limits
    if not get_dynamic_rate_limit(client_ip, is_shadow):
        return JSONResponse({"error": "Dynamic Rate Limit Exceeded"}, status_code=429)

    # 3. SMART ROUTING (ML)
    # Decide which regional backend node to use
    target_node = get_smart_route(client_node_id=1, server_nodes=[10, 50, 100])
    request.state.target = target_node

    # 4. CACHING (Non-ML Performance)
    cache_key = f"cache:{request.url.path}"
    if cached := r.get(cache_key):
        return Response(content=cached, media_type="application/json", headers={"X-AI-Cache": "HIT"})

    # 5. SELF-HEALING (Non-ML Circuit Breaker)
    if r.get("circuit:status") == "OPEN":
        return JSONResponse({"error": "Service in Self-Healing mode"}, status_code=503)

    try:
        response = await call_next(request)
        # Reset circuit on success
        r.delete(f"fails:{client_ip}")
        return response
    except Exception:
        # Trigger Circuit Breaker (Trip after 5 fails)
        fails = r.incr(f"fails:{client_ip}")
        if fails > 5:
            r.setex("circuit:status", 30, "OPEN")
        raise HTTPException(status_code=500, detail="Backend Failure")

# --- 4. PREDICTIVE AUTO-SCALING (Background Task) ---

@app.get("/system/predict-load")
async def forecast():
    """Predictive Scaling: Forecasts next hour traffic using NASA model."""
    # Mock current state
    hour, day, last_hour_count = 14, 2, 5000 
    prediction = scaling_model.predict([[hour, day, last_hour_count]])[0]
    
    return {
        "current_hour": hour,
        "predicted_requests_next_hour": int(prediction),
        "scaling_action": "SCALE_UP" if prediction > 6000 else "STABLE"
    }

# 1. Add the main optimized endpoint
@app.get("/optimize")
async def get_optimized():
    return {"message": "Request processed by AI Optimizer", "status": "success"}

# 2. Add the failure test endpoint for the Circuit Breaker test
@app.get("/fail-test-route")
async def fail_route():
    # We force a 500 error here to test if the Circuit Breaker trips
    from fastapi import HTTPException
    raise HTTPException(status_code=500, detail="Simulated Backend Failure")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)