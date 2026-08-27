import { randomUUID } from "node:crypto";
import { Router, type IRouter } from "express";
import { MLClient } from "../services/ml-client";
import { dataStore } from "../services/store";
import { wsHub } from "../services/websocket";
import { ThreatCorrelationEngine } from "../services/correlation";

const router: IRouter = Router();

// ---------------------------------------------------------------------------
// In-process sensor gate (external sensor is scripts/network-sensor.py).
// The gate controls whether the API accepts or rejects incoming telemetry.
// When stopped, the Python sensor will receive 503 responses and back off.
// ---------------------------------------------------------------------------
interface SensorStatus {
  enabled: boolean;
  stoppedAt: Date | null;
  startedAt: Date | null;
  flowsIngested: number;
}

const sensorState: SensorStatus = {
  enabled: true,
  stoppedAt: null,
  startedAt: new Date(),
  flowsIngested: 0
};

/** GET /network/sensor/status — Returns the current sensor gate status. */
router.get("/network/sensor/status", (_req, res) => {
  return res.json({
    enabled: sensorState.enabled,
    startedAt: sensorState.startedAt,
    stoppedAt: sensorState.stoppedAt,
    flowsIngested: sensorState.flowsIngested,
    message: sensorState.enabled
      ? "Network telemetry ingestion is ACTIVE. The sensor is accepting flow records."
      : "Network telemetry ingestion is PAUSED. No new flows or alerts will be generated until the sensor is restarted."
  });
});

/** POST /network/sensor/start — Re-enables telemetry ingestion. */
router.post("/network/sensor/start", (_req, res) => {
  if (sensorState.enabled) {
    return res.json({ enabled: true, message: "Sensor is already running." });
  }
  sensorState.enabled = true;
  sensorState.startedAt = new Date();
  sensorState.stoppedAt = null;
  wsHub.broadcast("SENSOR_STATUS", { enabled: true, startedAt: sensorState.startedAt });
  return res.json({ enabled: true, startedAt: sensorState.startedAt, message: "Sensor started. Telemetry ingestion is now active." });
});

/** POST /network/sensor/stop — Pauses telemetry ingestion (no new flows or alerts). */
router.post("/network/sensor/stop", (_req, res) => {
  if (!sensorState.enabled) {
    return res.json({ enabled: false, message: "Sensor is already stopped." });
  }
  sensorState.enabled = false;
  sensorState.stoppedAt = new Date();
  wsHub.broadcast("SENSOR_STATUS", { enabled: false, stoppedAt: sensorState.stoppedAt });
  return res.json({ enabled: false, stoppedAt: sensorState.stoppedAt, message: "Sensor stopped. No new telemetry will be ingested until restarted." });
});

/**
 * POST /network/telemetry
 * Real Network Flow Ingestion Endpoint
 * Compatible with Zeek conn.log / Suricata eve.json / Flow collectors.
 * Returns 503 when the sensor gate is stopped.
 */
router.post("/network/telemetry", async (req, res) => {
  // Gate: reject inbound telemetry if sensor is stopped
  if (!sensorState.enabled) {
    return res.status(503).json({
      error: "Network sensor is stopped",
      message: "Telemetry ingestion is paused. Start the sensor to resume."
    });
  }

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
  sensorState.flowsIngested++;

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

export { sensorState };
export default router;
