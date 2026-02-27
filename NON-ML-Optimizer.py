import time
import json
import redis
import brotli_asgi
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from dicttoxml import dicttoxml
from typing import Optional

app = FastAPI(title="API Optimizer - Phase 1 Engine")

# --- CONFIGURATION & STATE ---
# Connect to Redis (Used for Caching, Rate Limiting, and Circuit Breaking)
r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# 1. BROTLI/GZIP COMPRESSION (Auto-negotiates based on Accept-Encoding)
app.add_middleware(brotli_asgi.BrotliMiddleware, quality=4)

# 2. CIRCUIT BREAKER STATE (Non-ML Self-Healing)
# Tracks failures of a backend service to "trip" the circuit
FAILURE_THRESHOLD = 5
RECOVERY_TIMEOUT = 30 # Seconds

# --- UTILITY FUNCTIONS ---

def get_token_bucket_limit(key: str, limit: int, period: int):
    """
    Fixed Token Bucket Rate Limiting logic using Redis.
    """
    now = time.time()
    pipe = r.pipeline()
    # Key stores: [current_tokens, last_updated_timestamp]
    pipe.get(f"ratelimit:{key}")
    res = pipe.execute()[0]
    
    if res:
        tokens, last_refill = json.loads(res)
        # Refill tokens based on elapsed time
        elapsed = now - last_refill
        tokens = min(limit, tokens + elapsed * (limit / period))
    else:
        tokens, last_refill = limit, now
        
    if tokens >= 1:
        # Request allowed
        r.setex(f"ratelimit:{key}", period, json.dumps([tokens - 1, now]))
        return True
    return False

# --- MIDDLEWARE & LOGIC ---

@app.middleware("http")
async def optimizer_core(request: Request, call_next):
    # a) HEALTH MONITORING & CIRCUIT BREAKER (Self-Healing)
    # Check if the "Circuit" is Open (service is considered broken)
    circuit_status = r.get("circuit_breaker:status")
    if circuit_status == "OPEN":
        # Check if we can attempt a reset (Half-Open)
        last_trip = float(r.get("circuit_breaker:last_trip") or 0)
        if time.time() - last_trip < RECOVERY_TIMEOUT:
            return JSONResponse({"error": "Service Temporarily Unavailable (Circuit Open)"}, status_code=503)

    # b) RATE LIMITING (Non-ML Fixed Logic)
    client_ip = request.client.host
    if not get_token_bucket_limit(client_ip, limit=100, period=60):
        return JSONResponse({"error": "Rate Limit Exceeded"}, status_code=429)

    # c) RESPONSE CACHING (Cache-Aside Pattern)
    cache_key = f"cache:{request.method}:{request.url.path}:{request.query_params}"
    cached_data = r.get(cache_key)
    if cached_data:
        return Response(content=cached_data, media_type="application/json", headers={"X-Cache": "HIT"})

    # --- FORWARD TO BACKEND ---
    try:
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # d) DATA MAPPING (Non-ML: JSON to XML if requested)
        if request.headers.get("Accept") == "application/xml":
            # Logic would normally consume response.body() here
            pass 

        # If successful, reset failure counter (Self-Healing reset)
        r.delete(f"failures:{request.url.path}")
        r.set("circuit_breaker:status", "CLOSED")

        # CACHE SUCCESSFUL RESPONSES (e.g., for 5 minutes)
        if response.status_code == 200 and request.method == "GET":
            # Buffer response for caching logic
            pass

        return response

    except Exception as e:
        # e) SELF-HEALING LOGIC (Non-ML Circuit Breaker Tripping)
        # Increment failure count in Redis
        fail_count = r.incr(f"failures:{request.url.path}")
        if fail_count >= FAILURE_THRESHOLD:
            r.setex("circuit_breaker:status", RECOVERY_TIMEOUT, "OPEN")
            r.set("circuit_breaker:last_trip", time.time())
        raise e

# --- ENDPOINTS ---

@app.get("/data")
async def get_paginated_data(page: int = 1, size: int = 10):
    """
    f) QUERY PAGINATION (Deterministic logic)
    """
    # Simulate DB data
    mock_db = [{"id": i, "name": f"Item {i}"} for i in range(100)]
    start = (page - 1) * size
    end = start + size
    return {
        "page": page,
        "size": size,
        "total": len(mock_db),
        "data": mock_db[start:end]
    }

@app.get("/translate")
async def translate_format():
    """
    g) DATA TRANSLATION (Deterministic JSON to XML)
    """
    data = {"status": "success", "message": "Phase 1 Active"}
    xml_data = dicttoxml(data)
    return Response(content=xml_data, media_type="application/xml")

@app.get("/health")
async def health_check():
    """
    h) HEALTH MONITORING (Up/Down Check)
    """
    return {"status": "healthy", "redis_connected": r.ping()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)