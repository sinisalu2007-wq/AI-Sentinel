# AI-Sentinel: Behavioral Anomaly Detection for Secure African Digital Infrastructure

> **Official Recognition (October 2026):** Selected as a **Representative Case** in the *AI Case Innovation Competition for African Youth* (organized by the Secretariat of the Chinese Follow-up Committee of FOCAC and implemented by the China–BRICS Artificial Intelligence Development and Cooperation Center)[cite: 1].  
> 📖 **Published Anthology:** [Collection of Innovative AI Applications by Young People in African Countries](https://mp.weixin.qq.com/s/L9MAp-Et4izSRM3vGOBsfg)

**AI-Sentinel** is a lightweight, machine-learning-powered Network Intrusion Detection System (NIDS) engineered to detect behavioral network anomalies across resource- and bandwidth-constrained digital infrastructure.

---

## Use Cases & Real-World Applications
AI-Sentinel is built for organizations and institutions that need continuous network threat visibility without expensive enterprise appliances or constant cloud connectivity:

- **University & Campus Networks:** Detects unauthorized port scanning, internal lateral movement, and bandwidth-draining malware across student and administrative subnets.
- **SMEs & Local Financial/Fintech Infrastructure:** Provides an early-warning layer against brute-force login attempts, suspicious outbound data exfiltration, and unusual off-hour traffic spikes.
- **Public Sector & Community Digital Hubs:** Monitors local servers and routers in areas with intermittent internet connectivity using on-premise ML inference and local MySQL logging.
- **Cybersecurity Training & SOC Labs:** Serves as a practical teaching and testing environment for IT students and junior analysts learning packet inspection, feature extraction, and ML-driven anomaly detection.

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
Tech Stack
Environment: Linux (Tested on Kali Linux / Ubuntu)

AI & Packet Engine: Python 3.8+, Scapy, Scikit-Learn, Pandas / NumPy

Backend & Storage: PHP 8+, MySQL / MariaDB

Quickstart & Usage
1. Clone the Repository
Bash
git clone [https://github.com/sinisalu2007-wq/AI-Sentinel.git](https://github.com/sinisalu2007-wq/AI-Sentinel.git)
cd AI-Sentinel
2. Install Python Dependencies
Bash
pip install scapy scikit-learn pandas numpy mysql-connector-python
3. Configure the Database & Dashboard
Import the SQL schema into your local MySQL server.

Update your database credentials in the PHP dashboard config and Python detector script.

Host the dashboard directory via Apache or Nginx.

4. Launch AI-Sentinel
Make the launcher script executable and start the monitoring engine:

Bash
chmod +x start_sentinel.sh
sudo ./start_sentinel.sh
(Note: Root/sudo privileges are required by Scapy for raw packet capture.)

5. Monitor Alerts
Open your browser and navigate to your local PHP dashboard (e.g., http://localhost/AI-Sentinel) to view real-time anomaly alerts, flagged IP addresses, and traffic logs.

Roadmap (v2.0)
[ ] Offline .pcap replay mode for reproducible benchmarking and testing.

[ ] Configurable anomaly contamination thresholds and severity tagging (Low / Medium / High).

[ ] Automated email/webhook alerting for critical network anomalies.

[ ] Exportable CSV/PDF incident reports from the administrator dashboard.

Author
Sini Salu — BSc in Information Technology, University of Rwanda – College of Science and Technology (UR-CST)

GitHub: @sinisalu2007-wq
