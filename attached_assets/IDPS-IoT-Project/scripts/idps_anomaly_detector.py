# scripts/idps_anomaly_detector.py

import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

df = pd.read_csv('packet_captures/output.csv')
df['Length'] = pd.to_numeric(df['Length'], errors='coerce').fillna(0)

model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
model.fit(df[['Length']])

df['anomaly'] = model.predict(df[['Length']])
df['anomaly'] = df['anomaly'].map({1: 'Normal', -1: 'Anomaly'})

os.makedirs('alerts', exist_ok=True)
df[df['anomaly'] == 'Anomaly'].to_csv('alerts/anomalies.csv', index=False)
joblib.dump(model, 'models/isolation_forest_model.pkl')

print(f"[✔] Detected {df['anomaly'].value_counts().get('Anomaly', 0)} anomalies.")
