import { randomUUID } from "node:crypto";
import { Router, type IRouter } from "express";
import { dataStore } from "../services/store";
import { wsHub } from "../services/websocket";

const router: IRouter = Router();

const SECRET_PATTERNS = [
  { name: "AWS Access Key", regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g, weight: 35 },
  { name: "GitHub Personal Access Token", regex: /gh[pousr]_[A-Za-z0-9_]{36,255}/g, weight: 35 },
  { name: "Private RSA / SSH Key", regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, weight: 40 },
  { name: "Stripe API Key", regex: /(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,99}/g, weight: 30 },
  { name: "Generic API Key / Bearer Token", regex: /(?:api[_-]?key|bearer\s+|secret[_-]?token)[\s:=]+["']?([a-zA-Z0-9_\-\.]{24,})["']?/gi, weight: 25 },
  { name: "Database Connection String", regex: /(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-]+:[^@]+@[a-zA-Z0-9_\-\.]+(?::\d+)?\/[a-zA-Z0-9_\-]+/gi, weight: 35 }
];

function maskSecret(text: string): string {
  if (text.length <= 8) return "********";
  return text.slice(0, 4) + "..." + text.slice(-4);
}

router.post("/secrets/scan", async (req, res) => {
  const { content, source = "Code/Text Input" } = req.body || {};
  if (!content || typeof content !== "string") {
    return res.status(400).json({ error: "content string is required" });
  }

  const findings: { name: string; masked: string; weight: number }[] = [];
  let sanitizedText = content;

  for (const pattern of SECRET_PATTERNS) {
    const matches = Array.from(content.matchAll(pattern.regex));
    for (const match of matches) {
      const rawVal = match[0];
      const masked = maskSecret(rawVal);
      findings.push({ name: pattern.name, masked, weight: pattern.weight });
      sanitizedText = sanitizedText.replace(rawVal, `[REDACTED_${pattern.name.toUpperCase().replace(/\s+/g, "_")}]`);
    }
  }

  const riskScore = findings.length ? Math.min(100, 20 + findings.reduce((sum, f) => sum + f.weight, 0)) : 0;
  const severity = riskScore >= 70 ? "CRITICAL" : riskScore >= 40 ? "HIGH" : "LOW";
  const now = new Date();

  if (findings.length > 0) {
    const secEvent = await dataStore.insertSecurityEvent({
      id: `evt-${randomUUID().slice(0, 8)}`,
      type: "SECRET_LEAK",
      title: `Secret Leak Detected: ${findings.map((f) => f.name).join(", ")}`,
      detail: `Found ${findings.length} sensitive credential(s) in inspected text from ${source}.`,
      severity,
      score: riskScore,
      source: "Secret Guard",
      metadata: JSON.stringify({ count: findings.length, types: findings.map((f) => f.name) }),
      timestamp: now
    });

    if (riskScore >= 60) {
      const alert = await dataStore.insertAlert({
        id: `ALT-${randomUUID().slice(0, 8).toUpperCase()}`,
        title: "High-Entropy Secret Exposed",
        source: "Secret Guard",
        severity,
        score: riskScore,
        status: "NEW",
        description: `Exposed sensitive credentials (${findings.map((f) => f.name).join(", ")}) were identified.`,
        evidence: JSON.stringify({ findings }),
        timestamp: now
      });
      wsHub.broadcast("ALERT_NEW", alert);
    }

    wsHub.broadcast("EVENT_NEW", secEvent);
  }

  return res.json({
    hasSecrets: findings.length > 0,
    findingsCount: findings.length,
    findings,
    riskScore,
    severity,
    sanitizedContent: sanitizedText,
    recommendation: findings.length > 0 ? "Immediately revoke and rotate all exposed credentials." : "No sensitive secrets detected."
  });
});

export default router;
