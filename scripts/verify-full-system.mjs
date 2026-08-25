const WebSocketClient = globalThis.WebSocket;

async function verify() {
  const fetch = globalThis.fetch;
  const results = {
    mlService: false,
    expressApi: false,
    webSocket: false,
    urlAnalysis: false,
    messageAnalysis: false,
    persistence: false,
    dynamicDashboard: false,
  };

  console.log("==================================================");
  console.log("       AI CYBERGUARD END-TO-END VERIFICATION      ");
  console.log("==================================================\n");

  // 1. Check ML Engine on port 8000
  console.log("[1/7] Testing ML Service on http://127.0.0.1:8000/health ...");
  try {
    const mlHealth = await (await fetch("http://127.0.0.1:8000/health", { signal: AbortSignal.timeout(3000) })).json();
    console.log("  -> ML Service Status:", mlHealth.status);
    console.log("  -> Loaded Models:", Object.keys(mlHealth.models).map(k => `${k} (v${mlHealth.models[k].version}, F1: ${mlHealth.models[k].f1_score})`).join(", "));
    results.mlService = mlHealth.status === "healthy" && mlHealth.models.url_classifier.loaded && mlHealth.models.message_nlp.loaded;
  } catch (err) {
    console.error("  -> ML Service Check FAILED:", err.message);
  }

  // 2. Check Express API on port 5000
  console.log("\n[2/7] Testing Express API on http://127.0.0.1:5000/api/healthz ...");
  try {
    const apiHealth = await (await fetch("http://127.0.0.1:5000/api/healthz", { signal: AbortSignal.timeout(3000) })).json();
    console.log("  -> API Health Status:", apiHealth.status);
    console.log("  -> Components:", JSON.stringify(apiHealth.components));
    results.expressApi = apiHealth.status === "healthy" || apiHealth.status === "degraded";
  } catch (err) {
    console.error("  -> Express API Check FAILED:", err.message);
  }

  // 3. Test Real-Time WebSocket Connection
  console.log("\n[3/7] Testing WebSocket Real-Time Stream on ws://127.0.0.1:5000/ws ...");
  let wsReceivedEvents = [];
  const ws = new WebSocketClient("ws://127.0.0.1:5000/ws");
  
  await new Promise((resolve) => {
    const timeout = setTimeout(() => {
      console.warn("  -> WebSocket connection timed out after 3s");
      resolve();
    }, 3000);

    ws.addEventListener("open", () => {
      console.log("  -> WebSocket connected successfully.");
      results.webSocket = true;
      clearTimeout(timeout);
      resolve();
    });

    ws.addEventListener("message", (event) => {
      try {
        const msg = JSON.parse(event.data.toString());
        wsReceivedEvents.push(msg);
      } catch {}
    });

    ws.addEventListener("error", (err) => {
      console.error("  -> WebSocket error:", err);
      clearTimeout(timeout);
      resolve();
    });
  });

  // 4. Test URL Analysis ML Pipeline
  console.log("\n[4/7] Testing URL Security Analyzer with genuine malicious input ...");
  const testUrl = "http://secure-paypal-login-update.com.verify-billing.xyz/auth?session=9482";
  try {
    const res = await (await fetch("http://127.0.0.1:5000/api/analysis/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: testUrl })
    })).json();

    console.log("  -> URL Classification:", res.classification);
    console.log("  -> Risk Score:", res.riskScore, "/ 100");
    console.log("  -> Confidence:", res.confidence, "%");
    console.log("  -> Extracted Indicators:", res.indicators);
    results.urlAnalysis = (res.classification === "MALICIOUS" || res.classification === "SUSPICIOUS") && res.riskScore >= 70;
  } catch (err) {
    console.error("  -> URL Analysis FAILED:", err.message);
  }

  // 5. Test Message Analysis NLP Pipeline
  console.log("\n[5/7] Testing Phishing Message Analyzer with genuine social-engineering text ...");
  const testMsg = "URGENT NOTICE: Your account has been suspended due to unauthorized access. Enter your password and one-time code immediately to confirm identity.";
  try {
    const res = await (await fetch("http://127.0.0.1:5000/api/analysis/message", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: testMsg })
    })).json();

    console.log("  -> Message Classification:", res.classification);
    console.log("  -> Risk Score:", res.riskScore, "/ 100");
    console.log("  -> Confidence:", res.confidence, "%");
    console.log("  -> Identified Signals:", res.signals.map(s => `${s.name} (+${s.weight})`).join(", "));
    results.messageAnalysis = (res.classification === "MALICIOUS" || res.classification === "SUSPICIOUS") && res.riskScore >= 70;
  } catch (err) {
    console.error("  -> Message Analysis FAILED:", err.message);
  }

  // Wait 500ms for WebSocket broadcasts to arrive
  await new Promise(r => setTimeout(r, 500));
  console.log(`  -> WebSocket Events Received during tests: ${wsReceivedEvents.length} messages`);
  if (wsReceivedEvents.some(m => m.type === "EVENT_NEW" || m.type === "ALERT_NEW")) {
    console.log("  -> Confirmed Real-Time Broadcast received via WebSocket!");
  }
  ws.close();

  // 6. Verify Database Persistence
  console.log("\n[6/7] Verifying Database Persistence (checking recent events & alerts) ...");
  try {
    const events = await (await fetch("http://127.0.0.1:5000/api/dashboard/events?limit=5")).json();
    const alerts = await (await fetch("http://127.0.0.1:5000/api/alerts")).json();
    console.log(`  -> Persisted Recent Events in DB: ${events.length} records`);
    console.log(`  -> Persisted Active Alerts in DB: ${alerts.length} records`);
    const hasUrlEvt = events.some(e => e.type === "URL_ANALYSIS");
    const hasMsgEvt = events.some(e => e.type === "MESSAGE_ANALYSIS");
    results.persistence = hasUrlEvt && hasMsgEvt && events.length > 0;
    console.log(`  -> Confirmed event persistence: URL event (${hasUrlEvt}), Message event (${hasMsgEvt})`);
  } catch (err) {
    console.error("  -> Persistence check FAILED:", err.message);
  }

  // 7. Verify Dynamic Dashboard Aggregate Posture
  console.log("\n[7/7] Verifying Dynamic Dashboard Calculations ...");
  try {
    const summary = await (await fetch("http://127.0.0.1:5000/api/dashboard/summary")).json();
    console.log("  -> Calculated Security Score:", summary.securityScore);
    console.log("  -> Calculated Threat Level:", summary.threatLevel);
    console.log("  -> Severity Breakdown: Critical =", summary.critical, "| High =", summary.high, "| Medium =", summary.medium, "| Low =", summary.low);
    console.log("  -> Total Real Scans in DB:", summary.totalScans);
    results.dynamicDashboard = typeof summary.securityScore === "number" && summary.totalScans > 0;
  } catch (err) {
    console.error("  -> Dashboard check FAILED:", err.message);
  }

  console.log("\n==================================================");
  console.log("               VERIFICATION SUMMARY               ");
  console.log("==================================================");
  for (const [key, passed] of Object.entries(results)) {
    console.log(`  ${passed ? "✅ PASS" : "❌ FAIL"} - ${key}`);
  }
  const allPassed = Object.values(results).every(v => v === true);
  console.log(`\nOverall Status: ${allPassed ? "ALL ENDPOINTS & PIPELINES OPERATIONAL" : "SOME CHECKS FAILED"}`);

  process.exit(allPassed ? 0 : 1);
}

verify().catch(e => {
  console.error("Fatal verification error:", e);
  process.exit(1);
});
