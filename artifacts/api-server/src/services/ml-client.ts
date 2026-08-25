import { logger } from "../lib/logger";

const ML_ENGINE_URL = process.env.ML_ENGINE_URL || "http://127.0.0.1:8000";

export interface MLUrlResult {
  classification: "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN";
  riskScore: number;
  confidence: number;
  summary: string;
  indicators: string[];
  signals: { name: string; detail: string; weight: number }[];
  featureContributions?: Record<string, number>;
  recommendation: string;
}

export interface MLMessageResult {
  classification: "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN";
  riskScore: number;
  confidence: number;
  summary: string;
  indicators: string[];
  signals: { name: string; detail: string; weight: number }[];
  tokenAttributions?: { token: string; category: string; weight: number }[];
  recommendation: string;
}

export interface MLNetworkResult {
  attackClass: "NORMAL" | "PORT_SCAN" | "DOS_DDOS" | "BRUTE_FORCE" | "BOTNET_ANOMALY";
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  riskScore: number;
  confidence: number;
  detail: string;
  flowMetrics: any;
}

export class MLClient {
  static async checkHealth(): Promise<{ status: string; details?: any }> {
    try {
      const res = await fetch(`${ML_ENGINE_URL}/health`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) {
        const data = await res.json();
        return { status: "healthy", details: data };
      }
      return { status: "degraded", details: `HTTP ${res.status}` };
    } catch {
      return { status: "offline", details: "ML Engine microservice is unreachable" };
    }
  }

  static async predictUrl(rawUrl: string): Promise<MLUrlResult> {
    try {
      const res = await fetch(`${ML_ENGINE_URL}/api/ml/url/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: rawUrl }),
        signal: AbortSignal.timeout(3500)
      });

      if (res.ok) {
        return (await res.json()) as MLUrlResult;
      }
    } catch (err) {
      logger.warn({ err }, "ML Engine URL prediction unavailable, using fallback heuristic classifier");
    }

    // Heuristic Fallback
    let url: URL;
    try {
      url = new URL(rawUrl.includes("://") ? rawUrl : `http://${rawUrl}`);
    } catch {
      return {
        classification: "UNKNOWN",
        riskScore: 50,
        confidence: 60,
        summary: "Invalid URL structure could not be analyzed.",
        indicators: ["Invalid URL syntax"],
        signals: [{ name: "Syntax error", detail: "URL could not be parsed safely.", weight: 50 }],
        recommendation: "Ensure the URL is well-formed."
      };
    }

    const hostname = url.hostname.toLowerCase();
    const indicators: string[] = [];
    const signals: { name: string; detail: string; weight: number }[] = [];

    if (url.protocol !== "https:") {
      indicators.push("No HTTPS transport");
      signals.push({ name: "Transport security", detail: "Unencrypted HTTP transport.", weight: 24 });
    }
    if (hostname.includes("xn--")) {
      indicators.push("Punycode domain");
      signals.push({ name: "Domain encoding", detail: "Punycode domain may obscure characters.", weight: 34 });
    }
    if (hostname.split(".").length > 3) {
      indicators.push("Deep subdomain chain");
      signals.push({ name: "Domain structure", detail: "Multiple subdomain levels increase spoofing risk.", weight: 18 });
    }
    if (/[0-9]{4,}/.test(hostname)) {
      indicators.push("Numeric domain pattern");
      signals.push({ name: "Domain pattern", detail: "Unusual numeric density in hostname.", weight: 15 });
    }
    if (url.username || url.password) {
      indicators.push("Embedded credentials");
      signals.push({ name: "URL obfuscation", detail: "Embedded user credentials hide destination.", weight: 30 });
    }

    const riskScore = Math.min(100, 8 + signals.reduce((sum, s) => sum + s.weight, 0));
    const classification = riskScore >= 65 ? "MALICIOUS" : riskScore >= 35 ? "SUSPICIOUS" : "SAFE";

    return {
      classification,
      riskScore,
      confidence: signals.length ? 90 : 85,
      summary: signals.length ? "Heuristic signals indicate potential risk." : "No high-risk structural patterns detected.",
      indicators,
      signals,
      recommendation: signals.length ? "Verify domain credentials through a trusted channel." : "Continue only if you trust the source."
    };
  }

  static async predictMessage(rawText: string): Promise<MLMessageResult> {
    try {
      const res = await fetch(`${ML_ENGINE_URL}/api/ml/message/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: rawText }),
        signal: AbortSignal.timeout(3500)
      });

      if (res.ok) {
        return (await res.json()) as MLMessageResult;
      }
    } catch (err) {
      logger.warn({ err }, "ML Engine Message NLP prediction unavailable, using fallback intent parser");
    }

    // Heuristic Fallback
    const rules = [
      ["Urgency language", /urgent|immediately|within \d+ hours|act now|suspend/i, 25, "Urgency & time-pressure language."],
      ["Credential request", /password|login|verify your account|one[- ]time code|otp|credentials/i, 28, "Requests for authentication credentials."],
      ["Financial incentive", /refund|invoice|payment|prize|gift card|wire transfer|crypto/i, 22, "Financial lure or incentive."],
      ["Impersonation cue", /ceo|administrator|support team|security team|helpdesk/i, 18, "Authority or organizational impersonation."]
    ] as const;

    const signals = rules.filter(([, pattern]) => pattern.test(rawText)).map(([name, , weight, detail]) => ({ name, detail, weight }));
    const indicators = signals.map((s) => s.name);
    const riskScore = Math.min(100, 5 + signals.reduce((sum, s) => sum + s.weight, 0));
    const classification = riskScore >= 65 ? "MALICIOUS" : riskScore >= 35 ? "SUSPICIOUS" : "SAFE";

    return {
      classification,
      riskScore,
      confidence: signals.length ? 92 : 80,
      summary: signals.length ? "Social engineering signals identified in message text." : "No overt social engineering indicators found.",
      indicators,
      signals,
      recommendation: signals.length ? "Do not click links or share credentials. Verify sender." : "Standard caution advised."
    };
  }

  static async predictNetworkFlow(flowData: any): Promise<MLNetworkResult> {
    try {
      const res = await fetch(`${ML_ENGINE_URL}/api/ml/network/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(flowData),
        signal: AbortSignal.timeout(3500)
      });

      if (res.ok) {
        return (await res.json()) as MLNetworkResult;
      }
    } catch (err) {
      logger.warn({ err }, "ML Engine Network IDS prediction unavailable, using fallback flow analyzer");
    }

    // Heuristic Fallback
    const isHighRate = flowData.packetCount > 1000 || (flowData.flowDurationMs < 50 && flowData.packetCount > 1);
    const isPortScan = flowData.synFlags > 0 && flowData.ackFlags === 0 && flowData.packetCount <= 3;

    if (isHighRate) {
      return {
        attackClass: "DOS_DDOS",
        severity: "CRITICAL",
        riskScore: 94,
        confidence: 88,
        detail: "High-rate flow surge detected.",
        flowMetrics: flowData
      };
    }
    if (isPortScan) {
      return {
        attackClass: "PORT_SCAN",
        severity: "HIGH",
        riskScore: 78,
        confidence: 85,
        detail: "Single SYN packet without handshake completion.",
        flowMetrics: flowData
      };
    }

    return {
      attackClass: "NORMAL",
      severity: "LOW",
      riskScore: 8,
      confidence: 90,
      detail: "Normal traffic flow characteristics.",
      flowMetrics: flowData
    };
  }
}
