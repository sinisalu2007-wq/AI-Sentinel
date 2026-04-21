from scapy.all import sniff, IP, TCP
import pandas as pd
from datetime import datetime

# This list will store our "Network Features"
network_data = []

def analyze_packet(packet):
    if packet.haslayer(IP):
        # Extract features that AI loves: Source, Destination, and Protocol
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        size = len(packet)
        time = datetime.now().strftime("%H:%M:%S")

        print(f"[{time}] Detected: {src} -> {dst} | Size: {size} bytes")
        
        # Save to our list
        network_data.append([time, src, dst, proto, size])

    # Stop after 20 packets for this test
    if len(network_data) >= 20:
        return True

print("🛡️ AI-Sentinel is now sniffing your network for data...")
sniff(prn=analyze_packet, stop_filter=analyze_packet)

# Convert to a DataFrame (CSV style) to show how we prepare data for AI
df = pd.DataFrame(network_data, columns=['Time', 'Source', 'Destination', 'Protocol', 'Size'])
print("\n--- Processed Data for AI Training ---")
print(df.head())

# Save it to our data folder
df.to_csv('data/network_log.csv', index=False)
print("\n✅ Data saved to data/network_log.csv")