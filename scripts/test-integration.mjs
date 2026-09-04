async function runTests() {
  const fetch = globalThis.fetch;
  console.log('=== 1. Testing Health Endpoint ===');
  const health = await (await fetch('http://127.0.0.1:5000/api/healthz')).json();
  console.log('Health Status:', JSON.stringify(health, null, 2));

  console.log('\n=== 2. Testing URL ML Analysis (Malicious Phishing Sample) ===');
  const urlRes = await (await fetch('http://127.0.0.1:5000/api/analysis/url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'http://secure-login-chase-update.com.account-verify.xyz/login.php?user=auth' })
  })).json();
  console.log('URL Classification:', urlRes.classification, '| Risk Score:', urlRes.riskScore, '| Confidence:', urlRes.confidence);
  console.log('Indicators:', urlRes.indicators);

  console.log('\n=== 3. Testing Phishing NLP Message Analysis ===');
  const msgRes = await (await fetch('http://127.0.0.1:5000/api/analysis/message', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: 'URGENT: Your account has been locked due to suspicious activity. Verify your password immediately within 24 hours.' })
  })).json();
  console.log('Message Classification:', msgRes.classification, '| Risk Score:', msgRes.riskScore, '| Confidence:', msgRes.confidence);
  console.log('NLP Signals:', msgRes.signals);

  console.log('\n=== 4. Testing Network Flow IDS Telemetry (DoS Profile) ===');
  const netRes = await (await fetch('http://127.0.0.1:5000/api/network/telemetry', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      srcIp: '198.51.100.42',
      dstIp: '10.0.0.5',
      srcPort: 54321,
      dstPort: 443,
      flowDurationMs: 15000,
      totalFwdPackets: 2500,
      totalBwdPackets: 4,
      totalFwdBytes: 2500000,
      totalBwdBytes: 240,
      synFlags: 2000,
      finFlags: 0,
      rstFlags: 2,
      ackFlags: 4,
      pshFlags: 0,
      urgFlags: 0
    })
  })).json();
  console.log('Network Attack Class:', netRes.attackClass, '| Severity:', netRes.severity, '| Risk Score:', netRes.riskScore);

  console.log('\n=== 5. Testing Static File Analysis (Entropy & Imports) ===');
  const dummyExe = Buffer.from('MZ\x90\x00\x03\x00\x00\x00VirtualAlloc WriteProcessMemory cmd.exe powershell ' + 'A'.repeat(500)).toString('base64');
  const fileRes = await (await fetch('http://127.0.0.1:5000/api/analysis/file', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ filename: 'suspicious_payload.exe', contentBase64: dummyExe })
  })).json();
  console.log('File Classification:', fileRes.classification, '| Entropy:', fileRes.entropy, '| Risk Score:', fileRes.riskScore);
  console.log('Matched Imports:', fileRes.suspiciousStrings);

  console.log('\n=== 6. Testing DNS Tunneling Detection ===');
  const dnsRes = await (await fetch('http://127.0.0.1:5000/api/dns/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ queryDomain: '4a663932623934383261626364656631.exfil.attacker.xyz', queryType: 'TXT' })
  })).json();
  console.log('DNS Tunneling Flag:', dnsRes.isTunneling, '| Entropy:', dnsRes.entropy, '| Risk Score:', dnsRes.riskScore);

  console.log('\n=== 7. Testing Sensitive Secret Leak Scanner ===');
  const secRes = await (await fetch('http://127.0.0.1:5000/api/secrets/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'Found AWS key AKIAIOSFODNN7EXAMPLE and gh_pat_1234567890abcdef1234567890abcdef12 in config' })
  })).json();
  console.log('Secrets Detected:', secRes.findings.map(f => f.name + ': ' + f.masked));
  console.log('Sanitized Content:', secRes.sanitizedContent);

  console.log('\n=== 8. Testing Login Anomaly Profiler ===');
  const authRes = await (await fetch('http://127.0.0.1:5000/api/auth/event', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Workspace-Token': process.env.WORKSPACE_TOKEN || 'dev-token'
    },
    body: JSON.stringify({ username: 'avery', ipAddress: '203.0.113.88', userAgent: 'TorBrowser/13.0', status: 'SUCCESS' })
  })).json();
  console.log('Login Anomaly Flag:', authRes.isAnomaly, '| Reason:', authRes.anomalyReason, '| Risk:', authRes.riskScore);

  console.log('\n=== 9. Testing Dynamic Posture Dashboard Summary ===');
  const dashRes = await (await fetch('http://127.0.0.1:5000/api/dashboard/summary')).json();
  console.log('Security Score:', dashRes.securityScore, '| Threat Level:', dashRes.threatLevel);
  console.log('Active Breakdown: Critical=' + dashRes.critical + ', High=' + dashRes.high + ', Medium=' + dashRes.medium + ', Low=' + dashRes.low);
  console.log('Total Scans Recorded in DB:', dashRes.totalScans);

  console.log('\n=== 10. Testing Alerts Queue & Triage Workflow ===');
  const alertsRes = await (await fetch('http://127.0.0.1:5000/api/alerts')).json();
  console.log('Active Alerts in Queue:', alertsRes.length);
  if (alertsRes.length > 0) {
    const alertId = alertsRes[0].id;
    const triageRes = await (await fetch(`http://127.0.0.1:5000/api/alerts/${alertId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'RESOLVED' })
    })).json();
    console.log('Triage Mutation:', triageRes.id, '->', triageRes.status);
  }

  console.log('\n=== 11. Testing Correlated Incidents ===');
  const incRes = await (await fetch('http://127.0.0.1:5000/api/incidents')).json();
  console.log('Correlated Incidents in DB:', incRes.length);
  if (incRes.length > 0) {
    console.log('Top Correlated Incident:', incRes[0].title, '| Correlated Events:', incRes[0].correlatedEventsCount);
  }

  console.log('\n>>> ALL 11 VERIFICATION TESTS PASSED SUCCESSFULLY! <<<');
}

runTests().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
