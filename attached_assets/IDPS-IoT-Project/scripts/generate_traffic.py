# scripts/generate_traffic.py

from scapy.all import *
import os

# Output pcap file
output_file = "packet_captures/simulated_traffic.pcap"

# Define normal IoT-like traffic (e.g., pings, MQTT)
normal_packets = []

# Simulated IoT device IPs
iot_device_1 = "192.168.1.10"
iot_device_2 = "192.168.1.11"
iot_gateway = "192.168.1.1"

# ICMP pings
for i in range(5):
    pkt = IP(src=iot_device_1, dst=iot_gateway)/ICMP()
    normal_packets.append(pkt)

# Simulate MQTT-like TCP traffic
for i in range(5):
    pkt = IP(src=iot_device_2, dst=iot_gateway)/TCP(sport=1883, dport=1883)/Raw(load="connect")
    normal_packets.append(pkt)

# Simulate suspicious burst (DoS style ping flood)
dos_packets = []
for i in range(100):  # high volume = anomaly
    pkt = IP(src="192.168.1.66", dst=iot_gateway)/ICMP()
    dos_packets.append(pkt)

# Combine all packets
all_packets = normal_packets + dos_packets

# Write to pcap
os.makedirs("packet_captures", exist_ok=True)
wrpcap(output_file, all_packets)

print(f"[✔] Simulated traffic saved to {output_file}")
