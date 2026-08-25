import fs from "node:fs";
import path from "node:path";

const WebSocketClient = globalThis.WebSocket;
const fetch = globalThis.fetch;

async function runEndToEndVerification() {
  console.log("================================================================================");
  console.log("            AI CYBERGUARD DEEP END-TO-END FUNCTIONAL VERIFICATION               ");
  console.log("================================================================================\n");

  // ---------------------------------------------------------------------------
  // TEST 1: URL Security Analyzer (Benign vs Suspicious/Malicious)
  // ---------------------------------------------------------------------------
  console.log(">>> [TEST 1] URL SECURITY ANALYZER (Multiple Real Inputs)");
  const urlTestInputs = [
    { url: "https://www.google.com/search?q=cybersecurity", expectedClass: "SAFE" },
    { url: "https://developer.mozilla.org/en-US/docs/Web/Security", expectedClass: "SAFE" },
    { url: "http://secure-login-chase-update.com.account-verify.xyz/login.php", expectedClass: "MALICIOUS" },
    { url: "http://192.168.1.100/admin/update/paypal-verification.html", expectedClass: "MALICIOUS" },
    { url: "http://signin.ebay.com.account-recovery-session8492.top/signin", expectedClass: "MALICIOUS" }
  ];

  for (const input of urlTestInputs) {
    const res = await (await fetch("http://127.0.0.1:5000/api/analysis/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: input.url })
    })).json();

    console.log(`  Input: ${input.url}`);
    console.log(`    -> Classification: ${res.classification} (Expected: ${input.expectedClass})`);
    console.log(`    -> Risk Score: ${res.riskScore}/100 | Confidence: ${res.confidence}%`);
    console.log(`    -> Indicators: ${res.indicators.length > 0 ? res.indicators.join(", ") : "None"}`);
    console.log(`    -> Recommendation: ${res.recommendation.slice(0, 60)}...`);
  }

  // ---------------------------------------------------------------------------
  // TEST 2: Message Phishing / Fraud NLP Analyzer (Benign vs Phishing)
  // ---------------------------------------------------------------------------
  console.log("\n>>> [TEST 2] MESSAGE PHISHING / FRAUD NLP ANALYZER");
  const messageTestInputs = [
    {
      msg: "Hi Avery, here are the meeting notes from our sprint planning earlier today. Let's sync up tomorrow morning.",
      expected: "SAFE"
    },
    {
      msg: "URGENT SECURITY ALERT: Your Microsoft 365 account has been locked. Verify your password and enter your OTP immediately within 24 hours.",
      expected: "MALICIOUS"
    },
    {
      msg: "Final Notice: Invoice #INV-98421 is past due. Execute the wire transfer immediately to avoid legal collection proceedings.",
      expected: "MALICIOUS"
    }
  ];

  for (const input of messageTestInputs) {
    const res = await (await fetch("http://127.0.0.1:5000/api/analysis/message", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: input.msg })
    })).json();

    console.log(`  Input Text: "${input.msg.slice(0, 65)}..."`);
    console.log(`    -> Classification: ${res.classification} (Expected: ${input.expected})`);
    console.log(`    -> Risk Score: ${res.riskScore}/100 | Confidence: ${res.confidence}%`);
    console.log(`    -> Signals: ${res.signals.map(s => `${s.name} (+${s.weight})`).join(", ") || "None"}`);
    console.log(`    -> Recommendation: ${res.recommendation.slice(0, 60)}...`);
  }

  // ---------------------------------------------------------------------------
  // TEST 3: Real-Time Telemetry via WebSocket Stream
  // ---------------------------------------------------------------------------
  console.log("\n>>> [TEST 3] REAL-TIME TELEMETRY & WEBSOCKET DISPATCH");
  const wsEvents = [];
  const ws = new WebSocketClient("ws://127.0.0.1:5000/ws");
  
  await new Promise((resolve) => {
    ws.addEventListener("open", () => {
      console.log("  -> WebSocket Client connected to ws://127.0.0.1:5000/ws");
      resolve();
    });
    ws.addEventListener("message", (event) => {
      try {
        const msg = JSON.parse(event.data.toString());
        wsEvents.push(msg);
      } catch {}
    });
  });

  // Trigger a fresh high-risk URL scan to observe the real-time broadcast
  console.log("  -> Submitting live detection trigger to /api/analysis/url ...");
  const liveTriggerRes = await (await fetch("http://127.0.0.1:5000/api/analysis/url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "http://bofa-alert-suspicious-login-unlock.work/auth/index.php" })
  })).json();

  // Wait 600ms for WebSocket delivery
  await new Promise(r => setTimeout(r, 600));
  console.log(`  -> WebSocket Messages Received: ${wsEvents.length}`);
  const eventBroadcast = wsEvents.find(m => m.type === "EVENT_NEW");
  const alertBroadcast = wsEvents.find(m => m.type === "ALERT_NEW");

  console.log(`  -> Event Broadcast Received: ${eventBroadcast ? `YES (${eventBroadcast.payload.title})` : "NO"}`);
  console.log(`  -> Alert Broadcast Received: ${alertBroadcast ? `YES (${alertBroadcast.payload.title}, Severity: ${alertBroadcast.payload.severity})` : "NO"}`);
  ws.close();

  // ---------------------------------------------------------------------------
  // TEST 4: Database Persistence & Dynamic Aggregations
  // ---------------------------------------------------------------------------
  console.log("\n>>> [TEST 4] DATABASE PERSISTENCE & DYNAMIC POSTURE");
  const events = await (await fetch("http://127.0.0.1:5000/api/dashboard/events?limit=10")).json();
  const alerts = await (await fetch("http://127.0.0.1:5000/api/alerts")).json();
  const summary = await (await fetch("http://127.0.0.1:5000/api/dashboard/summary")).json();

  console.log(`  -> Persisted Recent Events in DB: ${events.length} records`);
  console.log(`  -> Persisted Active Alerts in DB: ${alerts.length} records`);
  console.log(`  -> Latest 2 Events:`);
  events.slice(0, 2).forEach(e => console.log(`     - [${e.type}] ${e.title} (Score: ${e.score}, Severity: ${e.severity}, Timestamp: ${e.timestamp})`));
  console.log(`  -> Dynamic Dashboard Security Score: ${summary.securityScore}/100`);
  console.log(`  -> Dynamic Dashboard Threat Level: ${summary.threatLevel}`);
  console.log(`  -> Breakdown: Critical=${summary.critical}, High=${summary.high}, Medium=${summary.medium}, Low=${summary.low}`);
  console.log(`  -> Total Scans Recorded in DB: ${summary.totalScans}`);

  // ---------------------------------------------------------------------------
  // TEST 5: ML Models & Artifacts Inspection
  // ---------------------------------------------------------------------------
  console.log("\n>>> [TEST 5] MACHINE LEARNING MODELS & ARTIFACTS VERIFICATION");
  const modelsDir = path.resolve("services", "ml-engine", "models");
  const artifacts = ["url_model.joblib", "url_features.json", "message_nlp_model.joblib", "message_vectorizer.joblib", "message_features.json", "network_ids_model.joblib", "network_scaler.joblib", "network_metadata.json"];

  for (const art of artifacts) {
    const p = path.join(modelsDir, art);
    const exists = fs.existsSync(p);
    const size = exists ? fs.statSync(p).size : 0;
    console.log(`  Artifact: ${art} | Exists: ${exists} | Size: ${(size / 1024).toFixed(1)} KB`);
  }

  const urlMeta = JSON.parse(fs.readFileSync(path.join(modelsDir, "url_features.json"), "utf-8"));
  const msgMeta = JSON.parse(fs.readFileSync(path.join(modelsDir, "message_features.json"), "utf-8"));
  const netMeta = JSON.parse(fs.readFileSync(path.join(modelsDir, "network_metadata.json"), "utf-8"));

  console.log(`  -> URL Model: Type=${urlMeta.features.length} Features | F1=${urlMeta.metrics.f1} | Datasets=${urlMeta.dataset_sources.join(", ")}`);
  console.log(`  -> Message NLP: Type=TF-IDF N-Grams + Intent | F1=${msgMeta.metrics.f1} | Datasets=${msgMeta.dataset_sources.join(", ")}`);
  console.log(`  -> Network IDS: Classes=${netMeta.classes.join(", ")} | Weighted F1=${netMeta.metrics.f1} | Datasets=${netMeta.dataset_sources.join(", ")}`);

  // ---------------------------------------------------------------------------
  // TEST 6: Network IDS Ingestion Verification (Real Ingestion vs Test Data)
  // ---------------------------------------------------------------------------
  console.log("\n>>> [TEST 6] NETWORK IDS INGESTION PIPELINE VERIFICATION");
  const testFlow = {
    srcIp: "192.168.1.120",
    dstIp: "10.0.0.1",
    srcPort: 51234,
    dstPort: 80,
    protocol: "TCP",
    flowDurationMs: 45,
    totalFwdPackets: 2,
    totalBwdPackets: 0,
    totalFwdBytes: 88,
    totalBwdBytes: 0,
    synFlags: 2,
    finFlags: 0,
    rstFlags: 0,
    ackFlags: 0,
    pshFlags: 0,
    urgFlags: 0
  };

  const netRes = await (await fetch("http://127.0.0.1:5000/api/network/telemetry", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(testFlow)
  })).json();

  console.log(`  -> Flow Ingestion Input: ${testFlow.srcIp}:${testFlow.srcPort} -> ${testFlow.dstIp}:${testFlow.dstPort}`);
  console.log(`  -> Classified Attack Type: ${netRes.attackClass}`);
  console.log(`  -> Model Severity: ${netRes.severity} | Risk Score: ${netRes.riskScore} | Confidence: ${netRes.confidence}%`);
  console.log(`  -> Telemetry Source: Ingestion REST API (/api/network/telemetry) accepting Zeek/Suricata/Flow JSON objects.`);

  // ---------------------------------------------------------------------------
  // TEST 7: Health Endpoints
  // ---------------------------------------------------------------------------
  console.log("\n>>> [TEST 7] MULTI-SUBSYSTEM HEALTH REPORT");
  const apiHealth = await (await fetch("http://127.0.0.1:5000/api/healthz")).json();
  const mlHealth = await (await fetch("http://127.0.0.1:8000/health")).json();

  console.log("  Backend Health:", apiHealth.status);
  console.log("  ML Microservice Health:", mlHealth.status);
  console.log("  Database Mode:", apiHealth.components.database.mode);
  console.log("  WebSocket Hub:", apiHealth.components.websocketHub.status);

  console.log("\n================================================================================");
  console.log("                     END-TO-END VERIFICATION COMPLETE                           ");
  console.log("================================================================================");
}

runEndToEndVerification().catch(console.error);
