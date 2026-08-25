import { randomUUID } from "node:crypto";
import { Router, type IRouter } from "express";
import { dataStore } from "../services/store";
import { wsHub } from "../services/websocket";

const router: IRouter = Router();

export interface WifiNetworkItem {
  ssid: string;
  bssid?: string;
  security: string; // Open, WEP, WPA-Personal, WPA2-Personal, WPA3-Personal, WPA2-Enterprise
  signalStrength: number; // 0 - 100%
  channel?: number;
}

router.post("/wifi/scan", async (req, res) => {
  const { networks, clientHost = "Local Companion Agent" } = req.body || {};
  if (!Array.isArray(networks)) {
    return res.status(400).json({ error: "networks array is required" });
  }

  const evaluated = networks.map((net: WifiNetworkItem) => {
    let risk = 5;
    const flags: string[] = [];
    const sec = (net.security || "").toLowerCase();

    if (sec.includes("open") || sec.includes("none")) {
      risk = 75;
      flags.push("Unencrypted Open Wi-Fi Network (Vulnerable to eavesdropping)");
    } else if (sec.includes("wep")) {
      risk = 85;
      flags.push("Deprecated WEP Encryption (Broken cipher, easily cracked)");
    } else if (sec.includes("wpa-personal") && !sec.includes("wpa2") && !sec.includes("wpa3")) {
      risk = 60;
      flags.push("Legacy WPA-TKIP (Vulnerable to legacy key recovery)");
    } else if (sec.includes("wpa3")) {
      risk = 5;
      flags.push("Strong WPA3-SAE Encryption");
    } else {
      risk = 15;
      flags.push("Standard WPA2-AES Encryption");
    }

    return {
      ...net,
      riskScore: risk,
      severity: risk >= 75 ? "HIGH" : risk >= 50 ? "MEDIUM" : "LOW",
      flags
    };
  });

  const highRiskCount = evaluated.filter((n) => n.riskScore >= 60).length;
  const now = new Date();

  const secEvent = await dataStore.insertSecurityEvent({
    id: `evt-${randomUUID().slice(0, 8)}`,
    type: "WIFI_SECURITY",
    title: `Wi-Fi Diagnostic: ${networks.length} Networks Evaluated`,
    detail: `Telemetry from ${clientHost}: ${highRiskCount} insecure/open access points detected.`,
    severity: highRiskCount > 0 ? "HIGH" : "LOW",
    score: highRiskCount > 0 ? 65 : 10,
    source: "Wi-Fi Companion",
    metadata: JSON.stringify({ total: networks.length, highRisk: highRiskCount }),
    timestamp: now
  });

  wsHub.broadcast("EVENT_NEW", secEvent);

  return res.json({
    evaluatedNetworks: evaluated,
    summary: {
      total: networks.length,
      insecureCount: highRiskCount,
      recommendation: highRiskCount > 0 ? "Avoid connecting to unencrypted or WEP access points without a verified VPN tunnel." : "Nearby wireless posture meets defensive standards."
    }
  });
});

export default router;
