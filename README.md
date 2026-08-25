# AI CyberGuard — Real-Time AI Cybersecurity & Defensive SOC Platform

**AI CyberGuard** is a defensive Security Operations Center (SOC) and threat-intelligence platform powered by machine learning models, real-time WebSocket telemetry, and multi-vector correlation.

---

## 🌟 Key Capabilities & Status

| Vector / Module | Status | Methodology & Dataset |
|---|---|---|
| **URL Security Analyzer** | `IMPLEMENTED` | Scikit-learn Random Forest (26 lexical & domain structural features) trained on ISCX-URL2016, PhishTank, and Alexa/Tranco 1M. |
| **Phishing / Fraud NLP Detector** | `IMPLEMENTED` | Calibrated TF-IDF n-gram classifier + intent scoring (urgency, credential harvesting, financial coercion) trained on Nazario Phishing Corpus, SpamAssassin, and Enron. |
| **Network Flow IDS Monitor** | `IMPLEMENTED` | Multi-class Flow Classifier trained on CICIDS2017 & CSE-CIC-IDS2018 flow distributions (DoS/DDoS, Port Scan, Brute Force, Botnet C2). Ingestion ready for Zeek / Suricata flow logs. |
| **Threat Correlation Engine** | `IMPLEMENTED` | Multi-vector cross-telemetry correlation grouping linked attack signals across time windows into unified Incidents. |
| **Central Risk Engine (0–100)** | `IMPLEMENTED` | Calibrated scoring combining ML probabilities, heuristic evidence weights, and asset criticality. |
| **Real-Time SOC Telemetry** | `IMPLEMENTED` | WebSocket hub (`/ws`) dispatching live events, alerts, and incident updates to the React dashboard without page refresh. |
| **Defensive Wi-Fi Companion** | `IMPLEMENTED` | Local host companion (`scripts/wifi-companion.py`) querying native OS wireless APIs (`netsh wlan`) to evaluate wireless encryption posture. |
| **Static File Security Guard** | `IMPLEMENTED` | Shannon entropy calculation, MD5/SHA256 hashing, printable strings extraction, and PE header inspection. |
| **Defensive DNS Monitor** | `IMPLEMENTED` | Domain entropy calculation, DGA algorithmic detection, and DNS exfiltration/tunneling heuristic analysis. |
| **Identity & Login Anomaly** | `IMPLEMENTED` | Velocity checks, user baseline profiling, and brute-force attempt thresholding. |
| **Secret & Sensitive Data Leak Guard** | `IMPLEMENTED` | High-entropy credential scanner for AWS, GitHub PATs, Private Keys, JWTs, and database URLs with automated value masking. |
| **Privacy-First Chrome Extension** | `IMPLEMENTED` | Manifest V3 on-demand URL threat shield without background browsing history logging. |

---

## 🏗️ Architecture

```
                             ┌───────────────────────────────────┐
                             │       AI CYBERGUARD SOC UI        │
                             │       (React 19 / Tailwind)       │
                             └─────────────────▲─────────────────┘
                                               │
                                 (REST API + WebSocket Stream)
                                               │
                             ┌─────────────────▼─────────────────┐
                             │        Express API Server         │
                             │  (Risk Engine, Router, WS Hub)    │
                             └─▲───────────────▲───────────────▲─┘
                               │               │               │
            ┌──────────────────┴──┐     ┌──────┴─────────┐     └───┬────────────────────────┐
            │                     │     │                │         │                        │
  ┌─────────┴─────────┐ ┌─────────┴─────┴──┐ ┌───────────┴─────────┴──┐ ┌──────────────────┴───────────────┐
  │   URL Analyzer    │ │ Phishing/Fraud   │ │   Network IDS Monitor   │ │    Defensive System Modules       │
  │ (Lexical, Domain, │ │ Message Analyzer │ │ (Zeek/Suricata Flow Log │ │ (Local Wi-Fi Companion Agent,     │
  │ DNS, SSL signals) │ │ (NLP Attributions│ │  Parser + Real Ingestion│ │  Static File Analyzer, DNS DGA,  │
  │                   │ │  Token Weights)  │ │  & IDS Telemetry)       │ │  Login Anomaly, Secret Leaker)    │
  └─────────┬─────────┘ └─────────┬────────┘ └───────────┬─────────────┘ └──────────────────┬────────────────┘
            │                     │                      │                                  │
            └─────────────────────┼──────────────────────┴──────────────────────────────────┘
                                  │
                                  ▼
                   ┌──────────────────────────────┐
                   │    Python AI/ML Service      │
                   │ (FastAPI Inference Engine)   │
                   │ • URL Classifier (RandomForest)
                   │ • NLP Phishing Model (TF-IDF)│
                   │ • Flow IDS Classifier (Flow) │
                   └──────────────┬───────────────┘
                                  │
                                  ▼
                   ┌──────────────────────────────┐
                   │  Central Risk Engine (0-100) │
                   │    & Threat Correlation      │
                   └──────────────┬───────────────┘
                                  │
                                  ▼
                   ┌──────────────────────────────┐
                   │ PostgreSQL / Drizzle DB      │
                   │ (Persistent Events, Scans,   │
                   │  Alerts, Correlated Incidents)
                   └──────────────────────────────┘
```

---

## 🚀 Running Locally

### 1. Prerequisites
- **Node.js**: v20+ (Node 24 recommended)
- **pnpm**: v9+ / v11+
- **Python**: 3.10+
- **PostgreSQL** *(Optional, automatically uses local persistent store if `DATABASE_URL` is omitted)*

### 2. Install Dependencies
```bash
# Install Node dependencies
pnpm install

# Install Python ML dependencies
python -m pip install fastapi uvicorn scikit-learn joblib numpy pandas requests pydantic
```

### 3. Train & Export Offline ML Models
```bash
python services/ml-engine/train_url_model.py
python services/ml-engine/train_message_nlp.py
python services/ml-engine/train_network_ids.py
```

### 4. Start the Python AI/ML Microservice (Port 8000)
```bash
python -m uvicorn main:app --app-dir services/ml-engine --port 8000 --host 127.0.0.1
```

### 5. Start the Express API & WebSocket Server (Port 5000)
```bash
# Build packages
pnpm run build

# Start server
node artifacts/api-server/dist/index.mjs
```

### 6. Run Integration Tests
```bash
node scripts/test-integration.mjs
```

### 7. Run Wi-Fi Local Companion Agent
```bash
python scripts/wifi-companion.py
```

---

## 🔒 Security Hardening & Defensive Principles

- **No Random/Simulated Data**: All dashboard metrics, scores, alerts, and distributions are dynamically computed from real persistent database records.
- **SSRF Defensive Guard**: URL analyzer blocks internal metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
- **Privacy-Preserving Extension**: Chrome Extension only inspects URLs when prompted by the user; does not track background browsing history.
- **Credential Masking**: Secret scanner masks discovered keys before storing event logs.
