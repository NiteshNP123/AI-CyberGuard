import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { Router, type IRouter } from "express";
import { MLClient } from "../services/ml-client";
import { dataStore } from "../services/store";
import { wsHub } from "../services/websocket";
import { ThreatCorrelationEngine } from "../services/correlation";
import { logger } from "../lib/logger";

const router: IRouter = Router();

// ---------------------------------------------------------------------------
// Unscored Telemetry Persistence Sink (Hardened & Fsynced)
// ---------------------------------------------------------------------------

let unscoredWriteQueue: Promise<void> = Promise.resolve();

/**
 * Persists an unscored telemetry record to an append-only JSONL sink
 * in an ignored runtime data path (.data/unscored_telemetry.jsonl).
 *
 * Guarantees:
 * 1. Concurrency safety: Writes are serialized through an internal queue to prevent
 *    interleaved chunks or race conditions.
 * 2. Directory creation: Explicitly verifies/creates parent directories before opening.
 * 3. Atomic line append: Exactly one full JSONL record terminated with '\n' is written.
 * 4. Physical durability: Calls FileHandle.sync() (fsync) to flush all data and metadata
 *    to physical storage before reporting success.
 * 5. Safe failure handling: Failures are logged with full server-side diagnostics while
 *    opaque, non-leaking error indicators are returned to the caller.
 */
export async function persistUnscoredTelemetry(
  record: Record<string, any>
): Promise<{ success: boolean; fsynced: boolean; error?: string }> {
  const dir = process.env.UNSCORED_TELEMETRY_DIR || path.resolve(process.cwd(), ".data");
  const filePath = process.env.UNSCORED_TELEMETRY_PATH || path.join(dir, "unscored_telemetry.jsonl");

  return new Promise<{ success: boolean; fsynced: boolean; error?: string }>((resolve) => {
    unscoredWriteQueue = unscoredWriteQueue
      .then(async () => {
        let handle: fs.promises.FileHandle | null = null;
        try {
          const parentDir = path.dirname(filePath);
          if (!fs.existsSync(parentDir)) {
            await fs.promises.mkdir(parentDir, { recursive: true });
          }

          handle = await fs.promises.open(filePath, "a");
          const line = JSON.stringify(record) + "\n";
          await handle.writeFile(line, "utf8");
          await handle.sync();

          resolve({ success: true, fsynced: true });
        } catch (err: any) {
          logger.error(
            { err, filePath, eventId: record.id },
            "Failed to append and synchronize unscored telemetry to JSONL audit sink"
          );
          resolve({ success: false, fsynced: false, error: "STORAGE_SINK_WRITE_FAILURE" });
        } finally {
          if (handle) {
            try {
              await handle.close();
            } catch (closeErr) {
              logger.warn({ closeErr, filePath }, "Error closing unscored telemetry file handle");
            }
          }
        }
      })
      .catch((fatalErr) => {
        logger.error({ fatalErr }, "Unexpected queue error in unscored telemetry persistence");
        resolve({ success: false, fsynced: false, error: "STORAGE_SINK_WRITE_FAILURE" });
      });
  });
}

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
    sensorPipeline,
    rawLog
  } = payload;

  // ---------------------------------------------------------------------------
  // TRANSITIONAL GUARD:
  // Ingested telemetry tagged with 'stateful_initiator_v2' uses initiator-directed
  // flow semantics and stateful lifecycle tracking that are incompatible with the
  // legacy synthetic model currently active in production.
  //
  // To protect active operations and prevent false alerts:
  // 1. Telemetry ingestion is acknowledged and recorded (flowsIngested counter incremented).
  // 2. ML inference is bypassed so the legacy model cannot emit unvalidated detections.
  // 3. No threat alerts or correlation events are generated.
  // 4. Returns an explicit, machine-readable UNSCORED_INCOMPATIBLE_PIPELINE status.
  // 5. Unscored telemetry is durably persisted and synchronized (FileHandle.sync())
  //    to an append-only JSONL audit sink in an ignored runtime directory (.data/).
  // 6. Data minimization: only allowlisted normalized flow fields are stored. Arbitrary
  //    payloads, credentials, or raw log blobs are excluded from persistent storage.
  // 7. Information disclosure prevention: internal paths and stack traces are logged
  //    server-side only and never leaked in client HTTP responses.
  // ---------------------------------------------------------------------------
  if (sensorPipeline === 'stateful_initiator_v2') {
    const eventId = `net-${randomUUID().slice(0, 8)}`;
    sensorState.flowsIngested++;

    // Explicitly allowlisted flow fields only (data minimization)
    const flowRecord = {
      id: eventId,
      timestamp: new Date().toISOString(),
      sensorPipeline: 'stateful_initiator_v2',
      scoringStatus: 'UNSCORED_INCOMPATIBLE_PIPELINE',
      srcIp: String(srcIp),
      dstIp: String(dstIp),
      srcPort: Number(srcPort),
      dstPort: Number(dstPort),
      protocol: String(protocol).toUpperCase(),
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
    };

    const persistResult = await persistUnscoredTelemetry(flowRecord);

    if (persistResult.success) {
      return res.status(202).json({
        id: eventId,
        status: 'UNSCORED_INCOMPATIBLE_PIPELINE',
        sensorPipeline: 'stateful_initiator_v2',
        activeModelVersion: 'legacy_synthetic_v1',
        durablyStored: true,
        fsynced: true,
        storageSink: 'jsonl_audit_sink',
        message: 'Telemetry received, durably stored, and synchronized to storage via FileHandle.sync() with stateful_initiator_v2 pipeline. ML scoring and alert generation are bypassed because the active backend model is legacy synthetic v1. Candidate model promotion pending.',
        detectionEnabled: false
      });
    }

    return res.status(202).json({
      id: eventId,
      status: 'UNSCORED_INCOMPATIBLE_PIPELINE',
      sensorPipeline: 'stateful_initiator_v2',
      activeModelVersion: 'legacy_synthetic_v1',
      durablyStored: false,
      fsynced: false,
      storageError: 'STORAGE_SINK_WRITE_FAILURE',
      message: 'Telemetry received into memory but NOT durably stored due to sink write failure. ML scoring and alert generation are bypassed because the active backend model is legacy synthetic v1.',
      detectionEnabled: false
    });
  }

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
