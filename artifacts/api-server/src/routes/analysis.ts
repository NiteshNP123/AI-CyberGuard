import { randomUUID, createHash } from "node:crypto";
import { Router, type IRouter } from "express";
import { MLClient } from "../services/ml-client";
import { dataStore } from "../services/store";
import { wsHub } from "../services/websocket";
import { RiskEngine } from "../services/risk-engine";
import { ThreatCorrelationEngine } from "../services/correlation";

const router: IRouter = Router();

// 1. URL Security Analyzer
router.post("/analysis/url", async (req, res) => {
  const { url } = req.body || {};
  if (!url || typeof url !== "string" || url.length < 3) {
    return res.status(400).json({ error: "Enter a valid URL to analyze." });
  }

  // SSRF Protection: Ensure defensive inspection only, prevent internal metadata probing
  try {
    const testUrl = new URL(url.includes("://") ? url : `http://${url}`);
    const host = testUrl.hostname.toLowerCase();
    if (host === "169.254.169.254" || host === "metadata.google.internal") {
      return res.status(400).json({ error: "Analysis of internal cloud metadata endpoints is restricted." });
    }
  } catch {
    return res.status(400).json({ error: "Invalid URL format." });
  }

  // Real ML Prediction & Feature Extraction
  const mlResult = await MLClient.predictUrl(url);

  // Central Risk Engine Scoring
  const riskEval = RiskEngine.evaluateRisk({
    baseScore: mlResult.riskScore,
    confidence: mlResult.confidence,
    indicatorsCount: mlResult.indicators.length,
    hasCredentialThreat: mlResult.indicators.some((i) => i.toLowerCase().includes("credential") || i.toLowerCase().includes("keyword"))
  });

  const scanId = `url-${randomUUID().slice(0, 8)}`;
  const now = new Date();

  // Save to persistent database
  await dataStore.insertUrlScan({
    id: scanId,
    url,
    domain: (() => {
      try { return new URL(url.includes("://") ? url : `http://${url}`).hostname; }
      catch { return url; }
    })(),
    classification: mlResult.classification,
    riskScore: riskEval.score,
    confidence: mlResult.confidence,
    summary: mlResult.summary,
    indicators: JSON.stringify(mlResult.indicators),
    signals: JSON.stringify(mlResult.signals),
    mlFeatures: JSON.stringify(mlResult.featureContributions || {}),
    recommendation: mlResult.recommendation
  });

  // Create unified security event
  const secEvent = await dataStore.insertSecurityEvent({
    id: `evt-${randomUUID().slice(0, 8)}`,
    type: "URL_ANALYSIS",
    title: mlResult.classification === "MALICIOUS" ? "Malicious URL Blocked" : mlResult.classification === "SUSPICIOUS" ? "Suspicious URL Flagged" : "Benign URL Inspected",
    detail: mlResult.summary,
    severity: riskEval.severity,
    score: riskEval.score,
    source: "URL Analyzer",
    metadata: JSON.stringify({ url, indicators: mlResult.indicators }),
    timestamp: now
  });

  // Create alert if high or critical
  if (riskEval.score >= 60) {
    const alert = await dataStore.insertAlert({
      id: `ALT-${randomUUID().slice(0, 8).toUpperCase()}`,
      title: mlResult.classification === "MALICIOUS" ? "Malicious Phishing/Credential URL" : "Suspicious Lookalike Domain",
      source: "URL Analyzer",
      severity: riskEval.severity,
      score: riskEval.score,
      status: "NEW",
      description: `URL [${url}] exhibited high-risk characteristics: ${mlResult.indicators.join(", ")}`,
      evidence: JSON.stringify({ url, signals: mlResult.signals, mlFeatures: mlResult.featureContributions }),
      timestamp: now
    });
    wsHub.broadcast("ALERT_NEW", alert);
  }

  // Trigger real-time WebSocket broadcast & Correlation
  wsHub.broadcast("EVENT_NEW", secEvent);
  await ThreatCorrelationEngine.evaluateEvent(secEvent);

  const responseData = {
    id: scanId,
    classification: mlResult.classification,
    riskScore: riskEval.score,
    confidence: mlResult.confidence,
    summary: mlResult.summary,
    indicators: mlResult.indicators,
    signals: mlResult.signals,
    recommendation: mlResult.recommendation,
    analyzedAt: now.toISOString()
  };

  return res.json(responseData);
});

// 2. Phishing / Fraud Message NLP Analyzer
router.post("/analysis/message", async (req, res) => {
  const { message } = req.body || {};
  if (!message || typeof message !== "string" || message.length < 10) {
    return res.status(400).json({ error: "Paste at least 10 characters of message text." });
  }

  // Real NLP Model Inference
  const mlResult = await MLClient.predictMessage(message);

  const riskEval = RiskEngine.evaluateRisk({
    baseScore: mlResult.riskScore,
    confidence: mlResult.confidence,
    indicatorsCount: mlResult.indicators.length,
    hasCredentialThreat: mlResult.indicators.some((i) => i.toLowerCase().includes("credential"))
  });

  const scanId = `msg-${randomUUID().slice(0, 8)}`;
  const now = new Date();

  // Save to persistent database
  await dataStore.insertMessageScan({
    id: scanId,
    message,
    classification: mlResult.classification,
    riskScore: riskEval.score,
    confidence: mlResult.confidence,
    summary: mlResult.summary,
    indicators: JSON.stringify(mlResult.indicators),
    signals: JSON.stringify(mlResult.signals),
    tokenAttributions: JSON.stringify(mlResult.tokenAttributions || []),
    recommendation: mlResult.recommendation
  });

  // Create unified security event
  const secEvent = await dataStore.insertSecurityEvent({
    id: `evt-${randomUUID().slice(0, 8)}`,
    type: "MESSAGE_ANALYSIS",
    title: mlResult.classification === "MALICIOUS" ? "Phishing Message Quarantined" : mlResult.classification === "SUSPICIOUS" ? "Social Engineering Detected" : "Message Verified Clean",
    detail: mlResult.summary,
    severity: riskEval.severity,
    score: riskEval.score,
    source: "Message Analyzer",
    metadata: JSON.stringify({ indicators: mlResult.indicators }),
    timestamp: now
  });

  // Create alert if high risk
  if (riskEval.score >= 60) {
    const alert = await dataStore.insertAlert({
      id: `ALT-${randomUUID().slice(0, 8).toUpperCase()}`,
      title: "Phishing / Social-Engineering Attempt",
      source: "Message Analyzer",
      severity: riskEval.severity,
      score: riskEval.score,
      status: "NEW",
      description: `Message contained active fraud/phishing indicators: ${mlResult.indicators.join(", ")}`,
      evidence: JSON.stringify({ textSample: message.slice(0, 150), signals: mlResult.signals, tokenAttributions: mlResult.tokenAttributions }),
      timestamp: now
    });
    wsHub.broadcast("ALERT_NEW", alert);
  }

  // Broadcast & Correlate
  wsHub.broadcast("EVENT_NEW", secEvent);
  await ThreatCorrelationEngine.evaluateEvent(secEvent);

  const responseData = {
    id: scanId,
    classification: mlResult.classification,
    riskScore: riskEval.score,
    confidence: mlResult.confidence,
    summary: mlResult.summary,
    indicators: mlResult.indicators,
    signals: mlResult.signals,
    recommendation: mlResult.recommendation,
    analyzedAt: now.toISOString()
  };

  return res.json(responseData);
});

// 3. Static File Analyzer
router.post("/analysis/file", async (req, res) => {
  const { filename, contentBase64 } = req.body || {};
  if (!filename || !contentBase64) {
    return res.status(400).json({ error: "Filename and base64 encoded content required." });
  }

  const buffer = Buffer.from(contentBase64, "base64");
  const size = buffer.length;

  // Cryptographic Hashes
  const md5 = createHash("md5").update(buffer).digest("hex");
  const sha256 = createHash("sha256").update(buffer).digest("hex");

  // Shannon Entropy Calculation (0.0 - 8.0)
  const freq: Record<number, number> = {};
  for (let i = 0; i < size; i++) {
    const byte = buffer[i];
    freq[byte] = (freq[byte] || 0) + 1;
  }
  let rawEntropy = 0;
  for (const byte in freq) {
    const p = freq[byte] / size;
    rawEntropy -= p * Math.log2(p);
  }
  const entropyScore = Math.round(rawEntropy * 12.5); // scaled to 0-100

  // Printable Strings & Suspicious Imports Extraction
  const textContent = buffer.toString("utf-8", 0, Math.min(size, 200000));
  const suspiciousKeywords = [
    "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "powershell", "cmd.exe",
    "mimikatz", "certutil", "rundll32", "regsvr32", "wscript", "cscript", "ShellExecute",
    "URLDownloadToFile", "IsDebuggerPresent", "HttpSendRequest"
  ];
  const matchedStrings = suspiciousKeywords.filter((kw) => textContent.toLowerCase().includes(kw.toLowerCase()));

  // PE Header Check (MZ signature)
  const isPE = buffer.length > 2 && buffer[0] === 0x4D && buffer[1] === 0x5A;

  let riskScore = 10;
  const indicators: string[] = [];

  if (rawEntropy > 7.2) {
    riskScore += 35;
    indicators.push("High Shannon Entropy (likely packed or encrypted)");
  }
  if (matchedStrings.length > 0) {
    riskScore += Math.min(45, matchedStrings.length * 15);
    indicators.push(`Suspicious API/process imports: ${matchedStrings.slice(0, 4).join(", ")}`);
  }
  if (isPE && rawEntropy > 7.0) {
    riskScore += 20;
    indicators.push("PE executable with packed sections");
  }

  riskScore = Math.min(100, riskScore);
  const classification = riskScore >= 70 ? "MALICIOUS" : riskScore >= 40 ? "SUSPICIOUS" : "SAFE";

  const secEvent = await dataStore.insertSecurityEvent({
    id: `evt-${randomUUID().slice(0, 8)}`,
    type: "FILE_ANALYSIS",
    title: `File Scanned: ${filename}`,
    detail: `Static analysis: Entropy ${rawEntropy.toFixed(2)}/8.0, Hashes [MD5: ${md5.slice(0, 8)}..., SHA256: ${sha256.slice(0, 8)}...]`,
    severity: riskScore >= 70 ? "CRITICAL" : riskScore >= 40 ? "HIGH" : "LOW",
    score: riskScore,
    source: "Static File Guard",
    metadata: JSON.stringify({ filename, md5, sha256, entropy: rawEntropy, matchedStrings }),
    timestamp: new Date()
  });

  wsHub.broadcast("EVENT_NEW", secEvent);

  return res.json({
    filename,
    fileSize: size,
    md5,
    sha256,
    entropy: Number(rawEntropy.toFixed(3)),
    entropyScore,
    isPE,
    suspiciousStrings: matchedStrings,
    classification,
    riskScore,
    indicators,
    recommendation: riskScore >= 40 ? "Quarantine file. Do not execute in production." : "File exhibits benign static characteristics."
  });
});

export default router;