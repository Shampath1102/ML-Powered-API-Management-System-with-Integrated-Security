import joblib
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model

def test_model(name, model, scaler, attack_value):
    print(f"\n--- Testing {name} ---")
    cols = scaler.feature_names_in_
    # Create a DataFrame that looks exactly like a malicious row from the training set
    df = pd.DataFrame(np.zeros((1, len(cols))), columns=cols)
    
    # Fill standard attack indicators
    if 'Total Fwd Packets' in cols: df['Total Fwd Packets'] = attack_value
    if 'Fwd Packet Length Max' in cols: df['Fwd Packet Length Max'] = attack_value
    if 'Unnamed: 0' in cols: df['Unnamed: 0'] = 0
    
    scaled = scaler.transform(df)
    prediction = model.predict(scaled)
    
    # Handle different model types
    res = prediction[0] if not isinstance(prediction[0], (np.ndarray, list)) else prediction[0][0]
    print(f"Result (1 is Attack, 0 is Safe): {res}")
    return res

# Load your actual files
d_rf = joblib.load('DDoS/ddos_rf_model.joblib')
d_sc = joblib.load('DDoS/ddos_scaler.joblib')
i_rf = joblib.load('Injection Attack (SQLi,XSS)/injection_rf_model.joblib')
i_sc = joblib.load('Injection Attack (SQLi,XSS)/injection_scaler.joblib')

# Test with a huge value (to force an attack detection)
test_model("DDoS RF", d_rf, d_sc, 999999)
test_model("Injection RF", i_rf, i_sc, 999999)