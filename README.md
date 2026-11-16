# AI-Sentinel: Behavioral Anomaly Detection for Secure African Digital Infrastructure

> **Official Recognition (October 2026):** Selected as a **Representative Case** in the *AI Case Innovation Competition for African Youth* (organized by the Secretariat of the Chinese Follow-up Committee of FOCAC and implemented by the China–BRICS Artificial Intelligence Development and Cooperation Center)[cite: 1].  
> 📖 **Published Anthology:** [Collection of Innovative AI Applications by Young People in African Countries](https://mp.weixin.qq.com/s/L9MAp-Et4izSRM3vGOBsfg)

**AI-Sentinel** is a lightweight, machine-learning-powered Network Intrusion Detection System (NIDS) engineered to detect behavioral network anomalies across resource- and bandwidth-constrained digital infrastructure.

---

## Why AI-Sentinel?
Many enterprise intrusion detection systems rely on heavy cloud telemetry or static signature databases that struggle with zero-day behaviors and intermittent connectivity. AI-Sentinel is built around local operational constraints:
- **Edge-Friendly ML Inference:** Uses unsupervised **Isolation Forest** anomaly detection capable of running on standard local CPU hardware without cloud GPU dependencies.
- **Offline-Resilient Logging:** Stores packet telemetry and anomaly alerts locally in MySQL so IT administrators retain full visibility even during upstream internet disruptions.
- **Behavioral Threat Detection:** Flags statistical deviations in packet rates, port-access entropy, and flow durations rather than relying solely on known attack signatures.

---

## Core Features
- **Real-Time Packet Capture & Feature Extraction:** Captures live network traffic using Python and `Scapy`, extracting flow-level behavioral features (packet size, protocol distribution, inter-arrival timing, and port activity).
- **Unsupervised Anomaly Scoring:** Applies `Scikit-Learn`'s Isolation Forest model to establish baseline network behavior and flag anomalous outliers such as port scans, brute-force spikes, and unusual outbound transfers.
- **Administrator Web Dashboard:** Provides a local PHP/MySQL web interface for IT teams to monitor flagged flows, inspect source/destination metadata, and review alert timestamps.

---

## System Architecture
```text
[Network Interface] ──► [Python + Scapy Sniffer] ──► [Feature Extractor]
                                                            │
                                                            ▼
[PHP Web Dashboard] ◄── [MySQL Alert Database] ◄── [Isolation Forest Model]
