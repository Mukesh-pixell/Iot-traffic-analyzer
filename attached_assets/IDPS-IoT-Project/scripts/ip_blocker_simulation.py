# scripts/ip_blocker_simulation.py

import pandas as pd
import os

file = 'alerts/anomalies.csv'
if not os.path.exists(file):
    raise FileNotFoundError("Run idps_anomaly_detector.py first!")

df = pd.read_csv(file)
blocked_ips = df['Source'].dropna().unique()

print("🔥 Simulated IP Blocking:")
for ip in blocked_ips:
    print(f"🚫 Blocked IP: {ip}")
