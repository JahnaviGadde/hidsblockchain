import json
import sys
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf
import traceback

# Load models and scaler
scaler = joblib.load('scaler.pkl')
iso_forest = joblib.load('iso_forest.pkl')
ocsvm = joblib.load('ocsvm.pkl')
xgb_meta = joblib.load('xgb_meta.pkl')
autoencoder = tf.keras.models.load_model('autoencoder.h5')

# Features used by ML models
features = [
    'flow_duration', 'flow_bytes/s', 'flow_packets/s', 'packet_length_mean',
    'packet_length_std', 'subflow_fwd_packets', 'subflow_bwd_packets',
    'flow_iat_mean', 'flow_iat_max', 'syn_flag_count', 'ack_flag_count',
    'fwd_init_win_bytes', 'idle_mean', 'active_max', 'total_tcp_flow_time'
]

def analyze_alerts(alert_data):
    """
    Analyze alert data using multiple ML models.
    
    Args:
        alert_data (list): A list of dictionaries containing alert data.
    
    Returns:
        list: A list of dictionaries with predictions from each model.
    """
    try:
        # Convert input alert data to DataFrame and select required features
        df_alerts = pd.DataFrame(alert_data)
        df_alerts = df_alerts[features].replace([np.inf, -np.inf], np.nan).fillna(0)
        
        # Scale features using the pre-loaded scaler
        X_alerts_scaled = scaler.transform(df_alerts)

        # Autoencoder predictions: compute reconstruction error (MSE)
        ae_reconstructions = autoencoder.predict(X_alerts_scaled)
        mse = np.mean(np.square(X_alerts_scaled - ae_reconstructions), axis=1)
        ae_threshold = np.percentile(mse, 98)
        ae_preds = (mse >= ae_threshold).astype(int)

        # Isolation Forest predictions: convert 1 (normal) to 0, -1 (anomaly) to 1
        iso_preds = np.where(iso_forest.predict(X_alerts_scaled) == 1, 0, 1)
        
        # One-Class SVM predictions: convert 1 (normal) to 0, -1 (anomaly) to 1
        svm_preds = np.where(ocsvm.predict(X_alerts_scaled) == 1, 0, 1)
        
        # Ensemble meta-model: combine predictions from individual models
        meta_input = np.column_stack((ae_preds, iso_preds, svm_preds))
        final_predictions = xgb_meta.predict(meta_input)

        # Build results: each record includes predictions from all models
        results = []
        for idx in range(len(df_alerts)):
            result = {
                "autoencoder": bool(ae_preds[idx]),
                "isolation_forest": bool(iso_preds[idx]),
                "one_class_svm": bool(svm_preds[idx]),
                "ensemble": bool(final_predictions[idx])
            }
            results.append(result)

        return results
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()}

def load_alerts_from_file(file_path):
    """
    Load alert data from a JSON file.
    """
    with open(file_path, "r") as f:
        return json.load(f)

if __name__ == "__main__":
    # If a file is provided as an argument, load alerts from the file.
    if len(sys.argv) > 1:
        alerts_file = sys.argv[1]
        try:
            alert_data = load_alerts_from_file(alerts_file)
        except Exception as e:
            print(json.dumps({"error": f"Failed to load alerts from file: {str(e)}"}))
            sys.exit(1)
    else:
        alert_data = [
            {
                "flow_duration": 10,
                "flow_bytes/s": 500,
                "flow_packets/s": 20,
                "packet_length_mean": 150,
                "packet_length_std": 15,
                "subflow_fwd_packets": 5,
                "subflow_bwd_packets": 3,
                "flow_iat_mean": 0.1,
                "flow_iat_max": 0.3,
                "syn_flag_count": 2,
                "ack_flag_count": 8,
                "fwd_init_win_bytes": 1000,
                "idle_mean": 0.5,
                "active_max": 10,
                "total_tcp_flow_time": 30
            }
        ]
    
    # Run analysis
    results = analyze_alerts(alert_data)
    print(json.dumps(results, indent=2))
