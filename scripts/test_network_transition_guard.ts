/**
 * Request-Level Integration Tests for Network Ingestion Transition Guard
 * =======================================================================
 * Exercises the actual Express application over the HTTP wire to verify:
 * 1. Express request parsing preserves `sensorPipeline: "stateful_initiator_v2"`.
 * 2. Guard intercepts `stateful_initiator_v2` and returns HTTP 202 UNSCORED_INCOMPATIBLE_PIPELINE.
 * 3. MLClient.predictNetworkFlow() is completely bypassed (0 calls).
 * 4. No model-derived alert or threat-correlation event is generated or persisted.
 * 5. No fabricated attack class, severity, risk score, or confidence is returned or stored.
 * 6. Telemetry is durably written to an append-only JSONL audit sink and synchronized
 *    via FileHandle.sync() (durablyStored: true, fsynced: true).
 * 7. Data minimization: strictly allowlisted flow features only; rawLog and payload
 *    are excluded from persistent storage.
 * 8. Information disclosure prevention & failure handling: write failure returns safe
 *    opaque error code 'STORAGE_SINK_WRITE_FAILURE' without leaking internal paths or stack traces.
 * 9. Concurrency safety: multiple concurrent writes serialize cleanly without partial records.
 * 10. Legacy pipeline requests (explicitly tagged `legacy_v1` or untagged) preserve existing
 *     HTTP 200 behavior, model inference, and event persistence.
 * 11. Sensor gate controls (stop -> HTTP 503, start -> HTTP 202/200) operate properly.
 */

import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import type { AddressInfo } from "node:net";
import app from "../artifacts/api-server/src/app";
import { MLClient } from "../artifacts/api-server/src/services/ml-client";
import { dataStore } from "../artifacts/api-server/src/services/store";
import { sensorState } from "../artifacts/api-server/src/routes/network";

describe("Network Ingestion Transition Guard — Request-Level Integration", () => {
  let server: http.Server;
  let baseUrl: string;
  let originalPredict: typeof MLClient.predictNetworkFlow;
  let predictCalls: any[] = [];
  let testSinkDir: string;
  let testSinkFile: string;

  before(async () => {
    // Set up dedicated test sink in os.tmpdir()
    testSinkDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-test-sink-"));
    testSinkFile = path.join(testSinkDir, "test_unscored_telemetry.jsonl");
    process.env.UNSCORED_TELEMETRY_PATH = testSinkFile;

    // Start ephemeral server
    await new Promise<void>((resolve) => {
      server = http.createServer(app);
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}/api/network`;
        resolve();
      });
    });

    // Ensure sensor gate is enabled
    sensorState.enabled = true;
    sensorState.startedAt = new Date();
    sensorState.stoppedAt = null;

    // Spy on MLClient.predictNetworkFlow
    originalPredict = MLClient.predictNetworkFlow;
    MLClient.predictNetworkFlow = async (flowData: any) => {
      predictCalls.push(flowData);
      return originalPredict.call(MLClient, flowData);
    };
  });

  after(async () => {
    // Restore spy
    MLClient.predictNetworkFlow = originalPredict;
    delete process.env.UNSCORED_TELEMETRY_PATH;

    // Clean up temporary sink files
    try {
      if (fs.existsSync(testSinkDir)) {
        fs.rmSync(testSinkDir, { recursive: true, force: true });
      }
    } catch {
      // Ignore temp dir cleanup errors
    }

    // Clean up server
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  beforeEach(() => {
    predictCalls = [];
    process.env.UNSCORED_TELEMETRY_PATH = testSinkFile;
  });

  it("1. Express request parser preserves 'stateful_initiator_v2' without schema-stripping", async () => {
    const testPayload = {
      sensorPipeline: "stateful_initiator_v2",
      srcIp: "192.168.1.100",
      dstIp: "10.0.0.1",
      srcPort: 54321,
      dstPort: 80,
      protocol: "TCP",
      flowDurationMs: 250,
      totalFwdPackets: 5,
      totalBwdPackets: 4,
      totalFwdBytes: 600,
      totalBwdBytes: 1200
    };

    const res = await fetch(`${baseUrl}/telemetry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(testPayload)
    });

    assert.equal(res.status, 202, "Expected HTTP 202 Accepted for transition guard");
    const json = await res.json();
    assert.equal(
      json.sensorPipeline,
      "stateful_initiator_v2",
      "sensorPipeline must survive Express parsing and reach the response"
    );
  });

  it("2. Transition guard returns HTTP 202 with UNSCORED_INCOMPATIBLE_PIPELINE and detectionEnabled: false", async () => {
    const initialFlows = sensorState.flowsIngested;

    const payload = {
      sensorPipeline: "stateful_initiator_v2",
      srcIp: "172.16.0.5",
      dstIp: "192.168.10.25",
      srcPort: 49872,
      dstPort: 443,
      protocol: "TCP",
      flowDurationMs: 1240,
      totalFwdPackets: 12,
      totalBwdPackets: 10,
      totalFwdBytes: 2400,
      totalBwdBytes: 8500
    };

    const res = await fetch(`${baseUrl}/telemetry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    assert.equal(res.status, 202);
    const body = await res.json();

    // Verify contract fields
    assert.equal(body.status, "UNSCORED_INCOMPATIBLE_PIPELINE");
    assert.equal(body.sensorPipeline, "stateful_initiator_v2");
    assert.equal(body.detectionEnabled, false);
    assert.equal(body.activeModelVersion, "legacy_synthetic_v1");
    assert.match(body.id, /^net-[a-f0-9-]+$/);
    assert.match(body.message, /ML scoring and alert generation are bypassed/i);

    // Verify MLClient was NOT called
    assert.equal(predictCalls.length, 0, "MLClient.predictNetworkFlow MUST NOT be called!");

    // Verify in-memory counter incremented
    assert.equal(sensorState.flowsIngested, initialFlows + 1);
  });

  it("3. Guard emits NO fabricated attack class, severity, risk score, or confidence", async () => {
    const payload = {
      sensorPipeline: "stateful_initiator_v2",
      srcIp: "10.0.0.99",
      dstIp: "10.0.0.1",
      srcPort: 33452,
      dstPort: 22,
      protocol: "TCP",
      totalFwdPackets: 100, // Even with flood-like numbers, unscored telemetry MUST NOT be evaluated
      flowDurationMs: 10
    };

    const res = await fetch(`${baseUrl}/telemetry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const body = await res.json();

    assert.equal(body.attackClass, undefined, "attackClass must be absent from unscored response");
    assert.equal(body.severity, undefined, "severity must be absent from unscored response");
    assert.equal(body.riskScore, undefined, "riskScore must be absent from unscored response");
    assert.equal(body.confidence, undefined, "confidence must be absent from unscored response");
    assert.equal(body.detail, undefined, "detail must be absent from unscored response");
    assert.equal(body.telemetry, undefined, "telemetry must be absent from unscored response");
  });

  it("4. Guard does NOT persist alerts or security events to dataStore tables", async () => {
    const alertsBefore = await dataStore.getAlerts();
    const eventsBefore = await dataStore.getRecentEvents(100);

    const payload = {
      sensorPipeline: "stateful_initiator_v2",
      srcIp: "192.168.1.200",
      dstIp: "192.168.1.1",
      srcPort: 60000,
      dstPort: 53,
      protocol: "UDP",
      totalFwdPackets: 2,
      totalBwdPackets: 2,
      totalFwdBytes: 150,
      totalBwdBytes: 280
    };

    const res = await fetch(`${baseUrl}/telemetry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    assert.equal(res.status, 202);
    const body = await res.json();
    const eventId = body.id;

    const alertsAfter = await dataStore.getAlerts();
    const eventsAfter = await dataStore.getRecentEvents(100);

    // Alert count should not increase
    assert.equal(alertsAfter.length, alertsBefore.length, "No alert may be inserted for unscored flows");

    // No security event with this ID should exist in dataStore
    const matchingEvent = eventsAfter.find((e) => e.id === eventId);
    assert.equal(matchingEvent, undefined, "No security event record may be inserted for unscored flows");

    // Verify alerts do not contain references to the unscored event
    const matchingAlert = alertsAfter.find((a) => a.description?.includes(eventId) || a.evidence?.includes(eventId));
    assert.equal(matchingAlert, undefined, "No alert may reference an unscored event");
  });

  it("5. Guard durably writes unscored telemetry with FileHandle.sync() (durablyStored: true, fsynced: true)", async () => {
    const payload = {
      sensorPipeline: "stateful_initiator_v2",
      srcIp: "10.10.10.50",
      dstIp: "192.168.1.1",
      srcPort: 51234,
      dstPort: 80,
      protocol: "TCP",
      flowDurationMs: 450,
      totalFwdPackets: 8,
      totalBwdPackets: 6,
      totalFwdBytes: 1024,
      totalBwdBytes: 2048,
      synFlags: 1,
      finFlags: 1,
      rstFlags: 0,
      ackFlags: 14,
      pshFlags: 2,
      urgFlags: 0,
      rawLog: "DROP_ME_UNTRUSTED_RAW_LOG" // Testing data minimization
    };

    const res = await fetch(`${baseUrl}/telemetry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    assert.equal(res.status, 202);
    const body = await res.json();

    // Verify durable storage & fsync status in response
    assert.equal(body.durablyStored, true, "durablyStored must be true on successful sync");
    assert.equal(body.fsynced, true, "fsynced must be true after FileHandle.sync()");
    assert.equal(body.storageSink, "jsonl_audit_sink");
    assert.match(body.message, /FileHandle\.sync\(\)/i);

    // Verify actual file on disk
    assert.ok(fs.existsSync(testSinkFile), "JSONL sink file must exist on disk");
    const rawContent = fs.readFileSync(testSinkFile, "utf-8").trim();
    const lines = rawContent.split("\n");
    assert.ok(lines.length >= 1, "Sink must contain at least one record");

    const lastRecord = JSON.parse(lines[lines.length - 1]);
    assert.equal(lastRecord.id, body.id, "Sink record id must match response id");
    assert.equal(lastRecord.sensorPipeline, "stateful_initiator_v2");
    assert.equal(lastRecord.scoringStatus, "UNSCORED_INCOMPATIBLE_PIPELINE");
    assert.equal(lastRecord.srcIp, "10.10.10.50");
    assert.equal(lastRecord.dstIp, "192.168.1.1");
    assert.equal(lastRecord.srcPort, 51234);
    assert.equal(lastRecord.dstPort, 80);
    assert.equal(lastRecord.flowDurationMs, 450);
    assert.equal(lastRecord.totalFwdPackets, 8);
    assert.equal(lastRecord.totalBwdPackets, 6);
    assert.equal(lastRecord.totalFwdBytes, 1024);
    assert.equal(lastRecord.totalBwdBytes, 2048);
    assert.ok(lastRecord.timestamp, "Record must have an ISO timestamp");

    // DATA MINIMIZATION: rawLog and arbitrary non-allowlisted fields MUST NOT be persisted
    assert.equal(lastRecord.rawLog, undefined, "rawLog must NOT be persisted in unscored sink");
    assert.equal(lastRecord.payload, undefined);
    assert.equal(lastRecord.packetData, undefined);

    // Verify sink does NOT contain fabricated metrics
    assert.equal(lastRecord.attackClass, undefined);
    assert.equal(lastRecord.riskScore, undefined);
    assert.equal(lastRecord.severity, undefined);
    assert.equal(lastRecord.confidence, undefined);
  });

  it("6. Failure handling & information disclosure prevention: safe storageError without path leakage", async () => {
    // Force write failure by pointing to an invalid/illegal path
    process.env.UNSCORED_TELEMETRY_PATH = "Z:\\nonexistent_volume_root\\unscored.jsonl";

    const payload = {
      sensorPipeline: "stateful_initiator_v2",
      srcIp: "10.20.30.40",
      dstIp: "192.168.1.1",
      srcPort: 45678,
      dstPort: 443,
      protocol: "TCP"
    };

    const res = await fetch(`${baseUrl}/telemetry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    // Server must still respond cleanly with HTTP 202 (not crash with 500)
    assert.equal(res.status, 202);
    const body = await res.json();

    assert.equal(body.status, "UNSCORED_INCOMPATIBLE_PIPELINE");
    assert.equal(body.sensorPipeline, "stateful_initiator_v2");
    assert.equal(body.detectionEnabled, false);
    assert.equal(body.durablyStored, false, "durablyStored must be false when write fails");
    assert.equal(body.fsynced, false);
    assert.equal(body.storageError, "STORAGE_SINK_WRITE_FAILURE", "Must return safe opaque error code");
    assert.match(body.message, /NOT durably stored due to sink write failure/i);

    // CRITICAL: Ensure NO absolute file paths or system diagnostics leaked in HTTP response
    const bodyStr = JSON.stringify(body);
    assert.equal(bodyStr.includes("Z:\\"), false, "Absolute path must NOT be leaked in HTTP response");
    assert.equal(bodyStr.includes("nonexistent_volume_root"), false, "Directory name must NOT be leaked");
    assert.equal(bodyStr.includes("ENOENT"), false, "System error code must NOT be leaked");
  });

  it("7. Concurrency safety: multiple concurrent writes serialize cleanly without partial records", async () => {
    // Fire 6 concurrent requests to the sink
    const requests = Array.from({ length: 6 }, (_, i) => ({
      sensorPipeline: "stateful_initiator_v2",
      srcIp: `192.168.1.${10 + i}`,
      dstIp: "10.0.0.1",
      srcPort: 50000 + i,
      dstPort: 80,
      protocol: "TCP",
      flowDurationMs: 100 * (i + 1),
      totalFwdPackets: i + 1,
      totalBwdPackets: i + 1,
      totalFwdBytes: 100 * (i + 1),
      totalBwdBytes: 200 * (i + 1)
    }));

    const responses = await Promise.all(
      requests.map((p) =>
        fetch(`${baseUrl}/telemetry`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(p)
        }).then((r) => r.json())
      )
    );

    // All must be accepted and durably stored
    for (const r of responses) {
      assert.equal(r.status, "UNSCORED_INCOMPATIBLE_PIPELINE");
      assert.equal(r.durablyStored, true);
      assert.equal(r.fsynced, true);
    }

    // Inspect the file on disk: all 6 records must be complete valid JSON lines
    const rawContent = fs.readFileSync(testSinkFile, "utf-8").trim();
    const lines = rawContent.split("\n");
    // Should have previous test 5 record + 6 new records
    assert.ok(lines.length >= 7);

    const parsedIds = new Set<string>();
    for (const line of lines) {
      assert.ok(line.trim().length > 0);
      const parsed = JSON.parse(line);
      assert.ok(parsed.id);
      assert.equal(parsed.sensorPipeline, "stateful_initiator_v2");
      parsedIds.add(parsed.id);
    }

    for (const r of responses) {
      assert.ok(parsedIds.has(r.id), `Record ${r.id} must be in the synchronized sink`);
    }
  });

  it("8. Legacy pipeline explicitly tagged 'legacy_v1' evaluates via MLClient and returns HTTP 200", async () => {
    const payload = {
      sensorPipeline: "legacy_v1",
      srcIp: "192.168.1.50",
      dstIp: "10.0.0.1",
      srcPort: 49152,
      dstPort: 80,
      protocol: "TCP",
      flowDurationMs: 150,
      totalFwdPackets: 10,
      totalBwdPackets: 8,
      totalFwdBytes: 1200,
      totalBwdBytes: 1800,
      synFlags: 1,
      finFlags: 1,
      rstFlags: 0,
      ackFlags: 17,
      pshFlags: 2,
      urgFlags: 0
    };

    const res = await fetch(`${baseUrl}/telemetry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    assert.equal(res.status, 200, "Legacy v1 telemetry should return HTTP 200 OK");
    const body = await res.json();

    // Verify MLClient was invoked
    assert.equal(predictCalls.length, 1, "MLClient.predictNetworkFlow MUST be called for legacy_v1");

    // Verify legacy contract fields exist
    assert.ok(body.id, "Legacy response must include id");
    assert.ok(body.attackClass, "Legacy response must include attackClass");
    assert.ok(body.severity, "Legacy response must include severity");
    assert.equal(typeof body.riskScore, "number", "Legacy response must include numeric riskScore");
    assert.equal(typeof body.confidence, "number", "Legacy response must include numeric confidence");
    assert.ok(body.detail, "Legacy response must include detail");
    assert.ok(body.telemetry, "Legacy response must include telemetry");
  });

  it("9. Untagged legacy request proceeds through legacy detection path and returns HTTP 200", async () => {
    const payload = {
      // sensorPipeline intentionally omitted
      srcIp: "192.168.1.75",
      dstIp: "10.0.0.2",
      srcPort: 51234,
      dstPort: 443,
      protocol: "TCP",
      flowDurationMs: 80,
      totalFwdPackets: 4,
      totalBwdPackets: 4,
      totalFwdBytes: 500,
      totalBwdBytes: 800
    };

    const res = await fetch(`${baseUrl}/telemetry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    assert.equal(res.status, 200, "Untagged legacy telemetry should return HTTP 200 OK");
    const body = await res.json();

    assert.equal(predictCalls.length, 1, "MLClient.predictNetworkFlow MUST be called for untagged flows");
    assert.ok(body.attackClass);
    assert.equal(typeof body.riskScore, "number");
  });

  it("10. Sensor gate controls: stop returns HTTP 503, start resumes normal processing", async () => {
    // 1. Stop sensor gate
    const stopRes = await fetch(`${baseUrl}/sensor/stop`, { method: "POST" });
    assert.equal(stopRes.status, 200);
    const stopJson = await stopRes.json();
    assert.equal(stopJson.enabled, false);
    assert.equal(sensorState.enabled, false);

    // 2. Telemetry during stopped state must be rejected with 503
    const rejectedRes = await fetch(`${baseUrl}/telemetry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sensorPipeline: "stateful_initiator_v2" })
    });
    assert.equal(rejectedRes.status, 503, "Rejected telemetry must return HTTP 503");
    const rejectedJson = await rejectedRes.json();
    assert.equal(rejectedJson.error, "Network sensor is stopped");

    // 3. Restart sensor gate
    const startRes = await fetch(`${baseUrl}/sensor/start`, { method: "POST" });
    assert.equal(startRes.status, 200);
    const startJson = await startRes.json();
    assert.equal(startJson.enabled, true);
    assert.equal(sensorState.enabled, true);

    // 4. Ingestion resumes and is durably persisted
    const resumeRes = await fetch(`${baseUrl}/telemetry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sensorPipeline: "stateful_initiator_v2" })
    });
    assert.equal(resumeRes.status, 202);
    const resumeJson = await resumeRes.json();
    assert.equal(resumeJson.durablyStored, true);
    assert.equal(resumeJson.fsynced, true);
  });
});
