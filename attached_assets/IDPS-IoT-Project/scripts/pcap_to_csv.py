# scripts/pcap_to_csv.py

import pyshark
import csv
import os

input_file = 'packet_captures/simulated_traffic.pcapng'
output_file = 'packet_captures/output.csv'

if not os.path.exists(input_file):
    raise FileNotFoundError("Missing .pcapng file in packet_captures/")

capture = pyshark.FileCapture(input_file, only_summaries=False)

with open(output_file, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])

    for i, pkt in enumerate(capture):
        try:
            writer.writerow([
                i + 1,
                pkt.sniff_time,
                pkt.ip.src if 'IP' in pkt else 'N/A',
                pkt.ip.dst if 'IP' in pkt else 'N/A',
                pkt.transport_layer if pkt.transport_layer else 'N/A',
                pkt.length,
                pkt.highest_layer
            ])
        except Exception:
            continue

print(f"[✔] Converted {input_file} to CSV.")
