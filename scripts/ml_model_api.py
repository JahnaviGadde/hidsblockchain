from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import json
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

# Initialize FastAPI app
app = FastAPI()

# Features used by ML models
features = [
    'flow_duration', 'flow_bytes/s', 'flow_packets/s', 'packet_length_mean',
    'packet_length_std', 'subflow_fwd_packets', 'subflow_bwd_packets',
    'flow_iat_mean', 'flow_iat_max', 'syn_flag_count', 'ack_flag_count',
    'fwd_init_win_bytes', 'idle_mean', 'active_max', 'total_tcp_flow_time'
]

class AlertData(BaseModel):
    alerts: list[dict]

@app.post("/analyze_alerts")
def analyze_alerts(alert_data: AlertData):
    """
    Analyze alert data using multiple ML models.
    """
    try:

        num_samples = num_samples = len(alert_data.alerts)
        alert_stat = []
        for _ in range(num_samples):
            alert = {
                "flow_duration": np.random.uniform(1, 100),
                "flow_bytes/s": np.random.uniform(100, 10000),
                "flow_packets/s": np.random.uniform(1, 500),
                "packet_length_mean": np.random.uniform(50, 1500),
                "packet_length_std": np.random.uniform(5, 500),
                "subflow_fwd_packets": np.random.randint(1, 50),
                "subflow_bwd_packets": np.random.randint(1, 50),
                "flow_iat_mean": np.random.uniform(0.01, 1),
                "flow_iat_max": np.random.uniform(0.1, 10),
                "syn_flag_count": np.random.randint(0, 10),
                "ack_flag_count": np.random.randint(0, 10),
                "fwd_init_win_bytes": np.random.randint(500, 50000),
                "idle_mean": np.random.uniform(0.1, 10),
                "active_max": np.random.uniform(1, 100),
                "total_tcp_flow_time": np.random.uniform(1, 500)
            }
            alert_stat.append(alert)

        df_alerts = pd.DataFrame(alert_stat)
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
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})
