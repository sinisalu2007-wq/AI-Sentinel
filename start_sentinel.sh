#!/bin/bash

echo "🛡️ Starting AI-Sentinel Security Suite..."
# Clear old data so we start fresh
echo "Cleaning old logs..."
rm -f data/network_log.csv
rm -f data/anomaly_results.csv
# Recreate the data folder just in case
mkdir -p data
# 1. Start the PHP Dashboard in the background
cd web
php -S localhost:8080 > /dev/null 2>&1 &
echo "✅ Web Dashboard started at http://localhost:8080"

# 2. Start the Packet Sniffer in the background (needs sudo)
cd ..
sudo python3 src/main.py &
echo "✅ Network Sniffer is active."

# 3. Start the AI Detector in a loop
echo "✅ AI Brain is processing... Press [CTRL+C] to stop."
while true
do
    python3 src/detector.py > /dev/null 2>&1
    sleep 5 # Wait 5 seconds before next analysis
done

