import { randomUUID } from "node:crypto";
import { Router, type IRouter } from "express";
import { dataStore } from "../services/store";
import { wsHub } from "../services/websocket";

const router: IRouter = Router();

function calculateEntropy(str: string): number {
  if (!str) return 0;
  const freq: Record<string, number> = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const c in freq) {
    const p = freq[c] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

router.post("/dns/analyze", async (req, res) => {
  const { queryDomain, queryType = "A" } = req.body || {};
  if (!queryDomain || typeof queryDomain !== "string") {
    return res.status(400).json({ error: "queryDomain is required" });
  }

  const cleanDomain = queryDomain.toLowerCase().trim();
  const domainParts = cleanDomain.split(".");
  const subdomain = domainParts.slice(0, -2).join(".");
  const entropy = calculateEntropy(subdomain || cleanDomain);

  // Indicators
  const isHighEntropy = entropy > 3.8 && (subdomain.length > 15 || cleanDomain.length > 25);
  const isDga = isHighEntropy && /[0-9a-f]{8,}/i.test(subdomain);
  const isTunneling = (subdomain.length > 40 && entropy > 4.0) || /^[a-f0-9]{32,}\./i.test(cleanDomain);

  let riskScore = 8;
  const indicators: string[] = [];

  if (isTunneling) {
    riskScore = 92;
    indicators.push("DNS Tunneling pattern detected (encoded binary payload in label)");
  } else if (isDga) {
    riskScore = 75;
    indicators.push("High-entropy algorithmic generation (DGA) characteristics");
  } else if (isHighEntropy) {
    riskScore = 50;
    indicators.push("Elevated subdomain randomness");
  }

  const severity = riskScore >= 80 ? "CRITICAL" : riskScore >= 60 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW";
  const now = new Date();

  const secEvent = await dataStore.insertSecurityEvent({
    id: `evt-${randomUUID().slice(0, 8)}`,
    type: "DNS_ANOMALY",
    title: isTunneling ? "DNS Tunneling Detected" : isDga ? "DGA Domain Query" : "DNS Query Logged",
    detail: `DNS Query: ${cleanDomain} [Type: ${queryType}, Entropy: ${entropy.toFixed(2)}]`,
    severity,
    score: riskScore,
    source: "DNS Monitor",
    metadata: JSON.stringify({ queryDomain: cleanDomain, queryType, entropy }),
    timestamp: now
  });

  if (riskScore >= 60) {
    const alert = await dataStore.insertAlert({
      id: `ALT-${randomUUID().slice(0, 8).toUpperCase()}`,
      title: isTunneling ? "DNS Exfiltration / Tunneling" : "DGA C2 Resolution Query",
      source: "DNS Monitor",
      severity,
      score: riskScore,
      status: "NEW",
      description: `Suspicious DNS pattern identified in query: ${cleanDomain}`,
      evidence: JSON.stringify({ domain: cleanDomain, entropy: Number(entropy.toFixed(2)), indicators }),
      timestamp: now
    });
    wsHub.broadcast("ALERT_NEW", alert);
  }

  wsHub.broadcast("EVENT_NEW", secEvent);

  return res.json({
    queryDomain: cleanDomain,
    queryType,
    entropy: Number(entropy.toFixed(2)),
    isDga,
    isTunneling,
    riskScore,
    severity,
    indicators,
    recommendation: isTunneling || isDga ? "Block domain resolution at upstream DNS resolver." : "Domain resolution baseline normal."
  });
});

export default router;
