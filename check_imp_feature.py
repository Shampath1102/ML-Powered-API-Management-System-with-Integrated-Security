import joblib
import pandas as pd

def get_top_features(model_path, scaler_path):
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    
    # Get feature names from the scaler
    features = scaler.feature_names_in_
    # Get importance from the Random Forest
    importances = model.feature_importances_
    
    # Create a sorted list
    feat_imp = sorted(zip(features, importances), key=lambda x: x[1], reverse=True)
    
    print(f"\nTop 5 Important Features for {model_path}:")
    for i in range(5):
        print(f"{i+1}. {feat_imp[i][0]} (Weight: {feat_imp[i][1]:.4f})")

get_top_features('DDoS/ddos_rf_model.joblib', 'DDoS/ddos_scaler.joblib')
get_top_features('Injection Attack (SQLi,XSS)/injection_rf_model.joblib', 'Injection Attack (SQLi,XSS)/injection_scaler.joblib')