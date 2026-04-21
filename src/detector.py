import pandas as pd
from sklearn.ensemble import IsolationForest

# 1. Load the data you captured on your EliteBook
try:
    df = pd.read_csv('data/network_log.csv')
except FileNotFoundError:
    print("No data found! Run your sniffer script first.")
    exit()

# 2. Prepare Features (AI only understands numbers)
# We convert 'Protocol' and 'Size' into a format the AI can read
# For now, let's just use 'Protocol' and 'Size' as our simple features
X = df[['Protocol', 'Size']]

# 3. Initialize the Isolation Forest
# 'contamination' is the % of traffic we expect to be 'bad' (e.g., 5%)
model = IsolationForest(contamination=0.05, random_state=42)

# 4. Train and Predict
df['anomaly_score'] = model.fit_predict(X)

# 5. Results: 1 is Normal, -1 is an Anomaly!
anomalies = df[df['anomaly_score'] == -1]

print(f"Total Packets Analyzed: {len(df)}")
print(f"⚠️ Potential Threats Detected: {len(anomalies)}")
print("\n--- Details of Suspicious Activity ---")
print(anomalies)

# Save the findings for your PHP Dashboard to read
df.to_csv('data/anomaly_results.csv', index=False)