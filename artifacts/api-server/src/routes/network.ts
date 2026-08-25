import { randomUUID } from "node:crypto";
import { Router, type IRouter } from "express";
import { MLClient } from "../services/ml-client";
import { dataStore } from "../services/store";
import { wsHub } from "../services/websocket";
import { ThreatCorrelationEngine } from "../services/correlation";

const router: IRouter = Router();

/**
 * Real Network Flow Ingestion Endpoint
 * Compatible with Zeek conn.log / Suricata eve.json / Flow collectors.
 */
router.post("/network/telemetry", async (req, res) => {
  const payload = req.body || {};
  const {
    srcIp = "192.168.1.50",
    dstIp = "10.0.0.1",
    srcPort = 49152,
    dstPort = 80,
    protocol = "TCP",
    flowDurationMs = 150,
    totalFwdPackets = 10,
    totalBwdPackets = 8,
    totalFwdBytes = 1200,
    totalBwdBytes = 1800,
    synFlags = 1,
    finFlags = 1,
    rstFlags = 0,
    ackFlags = 17,
    pshFlags = 2,
    urgFlags = 0,
    rawLog
  } = payload;

  const mlResult = await MLClient.predictNetworkFlow({
    srcIp,
    dstIp,
    srcPort: Number(srcPort),
    dstPort: Number(dstPort),
    protocol,
    flowDurationMs: Number(flowDurationMs),
    totalFwdPackets: Number(totalFwdPackets),
    totalBwdPackets: Number(totalBwdPackets),
    totalFwdBytes: Number(totalFwdBytes),
    totalBwdBytes: Number(totalBwdBytes),
    synFlags: Number(synFlags),
    finFlags: Number(finFlags),
    rstFlags: Number(rstFlags),
    ackFlags: Number(ackFlags),
    pshFlags: Number(pshFlags),
    urgFlags: Number(urgFlags)
  });

  const eventId = `net-${randomUUID().slice(0, 8)}`;
  const now = new Date();

  // Save to persistent database
  const netRecord = await dataStore.insertNetworkEvent({
    id: eventId,
    srcIp,
    dstIp,
    srcPort: Number(srcPort),
    dstPort: Number(dstPort),
    protocol,
    flowDuration: Math.round(Number(flowDurationMs)),
    packetCount: Number(totalFwdPackets) + Number(totalBwdPackets),
    byteCount: Number(totalFwdBytes) + Number(totalBwdBytes),
    attackClass: mlResult.attackClass,
    severity: mlResult.severity,
    riskScore: mlResult.riskScore,
    confidence: mlResult.confidence,
    flowFeatures: JSON.stringify(mlResult.flowMetrics),
    rawTelemetry: rawLog || null
  });

  // Create unified security event
  const secEvent = await dataStore.insertSecurityEvent({
    id: `evt-${randomUUID().slice(0, 8)}`,
    type: "NETWORK_IDS",
    title: mlResult.attackClass === "NORMAL" ? "Normal Flow Telemetry" : `Network Attack: ${mlResult.attackClass}`,
    detail: `${mlResult.detail} [${srcIp}:${srcPort} -> ${dstIp}:${dstPort}]`,
    severity: mlResult.severity,
    score: mlResult.riskScore,
    source: "Network IDS",
    metadata: JSON.stringify({ srcIp, dstIp, srcPort, dstPort, attackClass: mlResult.attackClass }),
    timestamp: now
  });

  if (mlResult.riskScore >= 60) {
    const alert = await dataStore.insertAlert({
      id: `ALT-${randomUUID().slice(0, 8).toUpperCase()}`,
      title: `Network IDS Alert: ${mlResult.attackClass}`,
      source: "Network IDS",
      severity: mlResult.severity,
      score: mlResult.riskScore,
      status: "NEW",
      description: `${mlResult.detail} Originating from ${srcIp} targeting ${dstIp}:${dstPort}`,
      evidence: JSON.stringify({ flow: netRecord, metrics: mlResult.flowMetrics }),
      timestamp: now
    });
    wsHub.broadcast("ALERT_NEW", alert);
  }

  wsHub.broadcast("EVENT_NEW", secEvent);
  await ThreatCorrelationEngine.evaluateEvent(secEvent);

  return res.json({
    id: eventId,
    attackClass: mlResult.attackClass,
    severity: mlResult.severity,
    riskScore: mlResult.riskScore,
    confidence: mlResult.confidence,
    detail: mlResult.detail,
    telemetry: netRecord
  });
});

export default router;
