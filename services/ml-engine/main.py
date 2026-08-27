"""
AI CyberGuard - Production AI/ML Inference Service
FastAPI microservice executing inference over offline-trained, versioned cybersecurity models.
Provides explainable AI metrics (feature attributions, token weights, indicators, recommendations).
"""

import os
import sys
import re
import json
import joblib
import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

sys.path.insert(0, os.path.dirname(__file__))

from train_url_model import extract_url_features, FEATURE_NAMES
from train_message_nlp import INTENT_RULES

app = FastAPI(title="AI CyberGuard ML Inference Engine", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")

# Load Versioned Artifacts
try:
    url_model = joblib.load(os.path.join(MODELS_DIR, "url_model.joblib"))
    with open(os.path.join(MODELS_DIR, "url_features.json"), "r", encoding="utf-8") as f:
        url_metadata = json.load(f)
except Exception as e:
    print(f"Warning: Could not load URL model: {e}")
    url_model = None
    url_metadata = {}

try:
    message_model = joblib.load(os.path.join(MODELS_DIR, "message_nlp_model.joblib"))
    message_vectorizer = joblib.load(os.path.join(MODELS_DIR, "message_vectorizer.joblib"))
    with open(os.path.join(MODELS_DIR, "message_features.json"), "r", encoding="utf-8") as f:
        message_metadata = json.load(f)
except Exception as e:
    print(f"Warning: Could not load Message NLP model: {e}")
    message_model = None
    message_vectorizer = None
    message_metadata = {}

try:
    network_model = joblib.load(os.path.join(MODELS_DIR, "network_ids_model.joblib"))
    network_scaler = joblib.load(os.path.join(MODELS_DIR, "network_scaler.joblib"))
    with open(os.path.join(MODELS_DIR, "network_metadata.json"), "r", encoding="utf-8") as f:
        network_metadata = json.load(f)
except Exception as e:
    print(f"Warning: Could not load Network IDS model: {e}")
    network_model = None
    network_scaler = None
    network_metadata = {}

# Request/Response Schemas
class UrlPredictRequest(BaseModel):
    url: str

class MessagePredictRequest(BaseModel):
    message: str

class NetworkPredictRequest(BaseModel):
    srcIp: str
    dstIp: str
    srcPort: int
    dstPort: int
    protocol: str = "TCP"
    flowDurationMs: float = 100.0
    totalFwdPackets: int = 10
    totalBwdPackets: int = 8
    totalFwdBytes: int = 800
    totalBwdBytes: int = 1200
    synFlags: int = 1
    finFlags: int = 1
    rstFlags: int = 0
    ackFlags: int = 17
    pshFlags: int = 2
    urgFlags: int = 0

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "AI CyberGuard ML Inference Engine",
        "models": {
            "url_classifier": {
                "loaded": url_model is not None,
                "version": url_metadata.get("version", "unknown"),
                "f1_score": url_metadata.get("metrics", {}).get("f1", 0.0)
            },
            "message_nlp": {
                "loaded": message_model is not None,
                "version": message_metadata.get("version", "unknown"),
                "f1_score": message_metadata.get("metrics", {}).get("f1", 0.0)
            },
            "network_ids": {
                "loaded": network_model is not None,
                "version": network_metadata.get("version", "unknown"),
                "f1_score": network_metadata.get("metrics", {}).get("f1", 0.0)
            }
        }
    }

@app.post("/api/ml/url/predict")
def predict_url(req: UrlPredictRequest):
    if not url_model:
        raise HTTPException(status_code=503, detail="URL classification model is not loaded")

    features = extract_url_features(req.url)
    X = np.array([features])

    # Model inference
    prob = float(url_model.predict_proba(X)[0][1]) # Malicious probability (0.0 - 1.0)
    risk_score = int(round(prob * 100))

    # Feature attribution & explainability
    importances = url_metadata.get("importances", {})
    indicators = []
    signals = []
    feature_contributions = {}

    for name, val in zip(FEATURE_NAMES, features):
        importance = importances.get(name, 0.0)
        feature_contributions[name] = round(float(val), 4)

        if name == "is_https" and val == 0:
            indicators.append("No HTTPS encryption")
            signals.append({"name": "Transport security", "detail": "The URL uses unencrypted plaintext HTTP transport.", "weight": 20})
        elif name == "is_ip_host" and val == 1:
            indicators.append("Direct IP address host")
            signals.append({"name": "IP-based hostname", "detail": "Using an IP address directly instead of a domain name is common in evasive campaigns.", "weight": 35})
        elif name == "is_punycode" and val == 1:
            indicators.append("Punycode homograph domain")
            signals.append({"name": "Domain encoding", "detail": "Punycode (xn--) can obscure lookalike characters to deceive users.", "weight": 30})
        elif name == "subdomain_count" and val >= 2:
            indicators.append("Deep subdomain chain")
            signals.append({"name": "Domain structure", "detail": f"Contains {int(val)} subdomains, which increases impersonation risk.", "weight": int(val * 8)})
        elif name == "has_embedded_creds" and val == 1:
            indicators.append("Embedded credentials in URL")
            signals.append({"name": "URL obfuscation", "detail": "Credentials embedded in the URL structure can mask the true destination.", "weight": 32})
        elif name == "suspicious_tld_weight" and val > 0:
            indicators.append("High-risk top-level domain")
            signals.append({"name": "TLD reputation", "detail": "Top-level domain has a disproportionately high frequency of abusive registrations.", "weight": int(val)})
        elif name.startswith("has_") and val == 1 and name not in ["has_embedded_creds"]:
            kw = name.replace("has_", "").replace("_keyword", "")
            indicators.append(f"Sensitive credential token: {kw}")
            signals.append({"name": "Lexical indicator", "detail": f"Contains sensitive token '{kw}' frequently targeted in phishing.", "weight": 12})

    if risk_score >= 70:
        classification = "MALICIOUS"
        summary = "This URL exhibits high-confidence characteristics of a credential harvesting or phishing site."
        recommendation = "Do not open this URL or submit any credentials. Block at the perimeter."
    elif risk_score >= 35:
        classification = "SUSPICIOUS"
        summary = "This URL contains structural anomalies and risk indicators that warrant verification."
        recommendation = "Verify the domain through a known trusted bookmark before proceeding."
    else:
        classification = "SAFE"
        summary = "No significant structural or known threat indicators were detected."
        recommendation = "Continue only if you recognize the destination domain."

    confidence = int(round(max(prob, 1.0 - prob) * 100))

    return {
        "classification": classification,
        "riskScore": risk_score,
        "confidence": confidence,
        "summary": summary,
        "indicators": indicators,
        "signals": signals,
        "featureContributions": feature_contributions,
        "recommendation": recommendation,
        "modelMetrics": url_metadata.get("metrics", {})
    }

@app.post("/api/ml/message/predict")
def predict_message(req: MessagePredictRequest):
    if not message_model or not message_vectorizer:
        raise HTTPException(status_code=503, detail="Message NLP model is not loaded")

    text = req.message
    X = message_vectorizer.transform([text])
    prob = float(message_model.predict_proba(X)[0][1])

    # Extract NLP intent signals & token attributions
    indicators = []
    signals = []
    token_attributions = []

    for key, (pattern, weight, detail) in INTENT_RULES.items():
        matches = pattern.findall(text)
        if matches:
            indicators.append(key.replace("_", " ").title())
            signals.append({"name": key.replace("_", " ").title(), "detail": detail, "weight": weight})
            for m in set(matches):
                token_attributions.append({"token": m, "category": key, "weight": weight})

    # Base NLP probability combined with calibrated intent signals
    intent_weight_sum = sum(s["weight"] for s in signals)
    calibrated_score = int(round(min(100, (prob * 60) + (min(40, intent_weight_sum)))))

    if calibrated_score >= 70:
        classification = "MALICIOUS"
        summary = "High-confidence social-engineering attack detected with urgency and credential/financial triggers."
        recommendation = "Do not reply, click links, or provide information. Report and quarantine the communication."
    elif calibrated_score >= 35:
        classification = "SUSPICIOUS"
        summary = "Suspicious social-engineering patterns detected. Verify sender identity out-of-band."
        recommendation = "Contact the purported sender using an official, independently verified contact channel."
    else:
        classification = "SAFE"
        summary = "No prominent phishing or coercion markers were identified in the message text."
        recommendation = "Always maintain standard security hygiene when reviewing external messages."

    confidence = int(round(max(prob, 1.0 - prob) * 100)) if signals else 85

    return {
        "classification": classification,
        "riskScore": calibrated_score,
        "confidence": confidence,
        "summary": summary,
        "indicators": indicators,
        "signals": signals,
        "tokenAttributions": token_attributions,
        "recommendation": recommendation,
        "modelMetrics": message_metadata.get("metrics", {})
    }

@app.post("/api/ml/network/predict")
def predict_network_flow(req: NetworkPredictRequest):
    if not network_model or not network_scaler:
        raise HTTPException(status_code=503, detail="Network IDS model is not loaded")

    # Compute derived flow metrics
    dur_sec = max(req.flowDurationMs / 1000.0, 0.001)
    byte_rate = (req.totalFwdBytes + req.totalBwdBytes) / dur_sec
    packet_rate = (req.totalFwdPackets + req.totalBwdPackets) / dur_sec
    std_port = 1 if req.dstPort in [80, 443, 53, 22, 21, 25, 110, 143, 389, 636, 8080] else 0
    eph_port = 1 if req.dstPort > 1024 else 0

    flow_vector = [
        float(req.flowDurationMs),
        float(req.totalFwdPackets),
        float(req.totalBwdPackets),
        float(req.totalFwdBytes),
        float(req.totalBwdBytes),
        float(byte_rate),
        float(packet_rate),
        float(req.synFlags),
        float(req.finFlags),
        float(req.rstFlags),
        float(req.ackFlags),
        float(req.pshFlags),
        float(req.urgFlags),
        float(std_port),
        float(eph_port)
    ]

    X_scaled = network_scaler.transform([flow_vector])
    pred_idx = int(network_model.predict(X_scaled)[0])
    probs = network_model.predict_proba(X_scaled)[0]

    classes = network_metadata.get("classes", ["NORMAL", "PORT_SCAN", "DOS_DDOS", "BRUTE_FORCE", "BOTNET_ANOMALY"])
    attack_class = classes[pred_idx]
    confidence = int(round(float(probs[pred_idx]) * 100))

    if attack_class == "DOS_DDOS":
        severity = "CRITICAL"
        risk_score = 95
        detail = "Abnormal packet surge and high-rate volumetric flow consistent with DoS/DDoS flood."
    elif attack_class == "PORT_SCAN":
        severity = "HIGH"
        risk_score = 78
        detail = "Rapid TCP SYN probe across ports with incomplete handshakes."
    elif attack_class == "BRUTE_FORCE":
        severity = "HIGH"
        risk_score = 82
        detail = "Repetitive auth requests and rapid tear-downs on service port."
    elif attack_class == "BOTNET_ANOMALY":
        severity = "HIGH"
        risk_score = 75
        detail = "Periodic beaconing flow on non-standard port indicating potential C2 traffic."
    else:
        severity = "LOW"
        risk_score = 10
        detail = "Flow metrics and protocol exchanges conform to normal baseline."

    return {
        "attackClass": attack_class,
        "severity": severity,
        "riskScore": risk_score,
        "confidence": confidence,
        "detail": detail,
        "flowMetrics": {
            "durationMs": req.flowDurationMs,
            "byteRate": round(byte_rate, 2),
            "packetRate": round(packet_rate, 2),
            "packets": req.totalFwdPackets + req.totalBwdPackets,
            "bytes": req.totalFwdBytes + req.totalBwdBytes
        },
        "modelMetrics": network_metadata.get("metrics", {})
    }
