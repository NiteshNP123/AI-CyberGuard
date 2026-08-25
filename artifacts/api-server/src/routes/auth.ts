import { randomUUID } from "node:crypto";
import { Router, type IRouter } from "express";
import { dataStore } from "../services/store";
import { wsHub } from "../services/websocket";
import { ThreatCorrelationEngine } from "../services/correlation";

const router: IRouter = Router();

// ---------------------------------------------------------------------------
// Login Anomaly Detection with DB-persisted behavioral baselines
// ---------------------------------------------------------------------------
// Per-user baseline is loaded from PostgreSQL (or the local persistent store)
// on first access and upserted after every login event. This means behavioral
// profiles survive server restarts — unlike the previous in-memory-only map.
// ---------------------------------------------------------------------------

// In-session cache to avoid a DB round-trip on every login from the same user.
// Populated lazily from DB on first access per user per server session.
const sessionCache: Record<
  string,
  { knownIps: Set<string>; knownUserAgents: Set<string>; failedAttempts: number; lastLoginAt: number }
> = {};

router.post("/auth/event", async (req, res) => {
  const { username, ipAddress, userAgent, status = "SUCCESS" } = req.body || {};
  if (!username || !ipAddress) {
    return res.status(400).json({ error: "username and ipAddress are required" });
  }

  const uLower = username.toLowerCase();

  // Load baseline from DB into session cache if not already present
  if (!sessionCache[uLower]) {
    const persisted = await dataStore.getLoginProfile(uLower);
    if (persisted) {
      sessionCache[uLower] = {
        knownIps: new Set(persisted.knownIps),
        knownUserAgents: new Set(persisted.knownUserAgents),
        failedAttempts: persisted.failedAttempts,
        lastLoginAt: persisted.lastLoginAt.getTime()
      };
    } else {
      // First-ever login for this user — initialise and immediately persist
      sessionCache[uLower] = {
        knownIps: new Set([ipAddress]),
        knownUserAgents: new Set([userAgent || "unknown"]),
        failedAttempts: 0,
        lastLoginAt: Date.now()
      };
      await dataStore.upsertLoginProfile(uLower, {
        knownIps: [ipAddress],
        knownUserAgents: [userAgent || "unknown"],
        failedAttempts: 0,
        lastLoginAt: new Date()
      });
    }
  }

  const baseline = sessionCache[uLower];
  const isNewIp = !baseline.knownIps.has(ipAddress);
  const isNewUa = !!userAgent && !baseline.knownUserAgents.has(userAgent);

  let isAnomaly = false;
  let anomalyReason = "";
  let riskScore = 10;

  if (status === "FAILED") {
    baseline.failedAttempts += 1;
    if (baseline.failedAttempts >= 4) {
      isAnomaly = true;
      anomalyReason = `Brute-force / credential stuffing threshold exceeded (${baseline.failedAttempts} consecutive failed attempts)`;
      riskScore = 88;
    } else {
      riskScore = 30 + baseline.failedAttempts * 10;
    }
  } else {
    // SUCCESS path
    if (isNewIp && isNewUa) {
      isAnomaly = true;
      anomalyReason = "Sign-in from unfamiliar IP address and previously unseen device user-agent";
      riskScore = 68;
    } else if (isNewIp) {
      isAnomaly = true;
      anomalyReason = "Sign-in from newly observed IP address";
      riskScore = 48;
    }
    // Update baseline
    baseline.failedAttempts = 0;
    baseline.knownIps.add(ipAddress);
    if (userAgent) baseline.knownUserAgents.add(userAgent);
    baseline.lastLoginAt = Date.now();
  }

  // Persist updated baseline back to DB
  await dataStore.upsertLoginProfile(uLower, {
    knownIps: Array.from(baseline.knownIps),
    knownUserAgents: Array.from(baseline.knownUserAgents),
    failedAttempts: baseline.failedAttempts,
    lastLoginAt: new Date(baseline.lastLoginAt)
  });

  const severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" =
    riskScore >= 80 ? "CRITICAL" : riskScore >= 60 ? "HIGH" : riskScore >= 35 ? "MEDIUM" : "LOW";
  const now = new Date();

  const secEvent = await dataStore.insertSecurityEvent({
    id: `evt-${randomUUID().slice(0, 8)}`,
    type: "LOGIN_ANOMALY",
    title: isAnomaly ? `Login Anomaly: ${username}` : `Authentication Success: ${username}`,
    detail: isAnomaly
      ? anomalyReason
      : `Standard authentication for user ${username} from ${ipAddress}`,
    severity,
    score: riskScore,
    source: "Identity Guard",
    metadata: JSON.stringify({ username, ipAddress, userAgent, isAnomaly, status }),
    timestamp: now
  });

  if (isAnomaly && riskScore >= 60) {
    const alert = await dataStore.insertAlert({
      id: `ALT-${randomUUID().slice(0, 8).toUpperCase()}`,
      title: "Suspicious Account Access / Anomaly",
      source: "Identity Guard",
      severity,
      score: riskScore,
      status: "NEW",
      description: `Unusual authentication pattern on account [${username}]: ${anomalyReason}`,
      evidence: JSON.stringify({ username, ipAddress, userAgent, status, reason: anomalyReason }),
      timestamp: now
    });
    wsHub.broadcast("ALERT_NEW", alert);
  }

  wsHub.broadcast("EVENT_NEW", secEvent);
  await ThreatCorrelationEngine.evaluateEvent(secEvent);

  return res.json({
    username,
    ipAddress,
    status,
    isAnomaly,
    anomalyReason: anomalyReason || "Conforms to known user baseline",
    riskScore,
    severity
  });
});

// Expose known profile for debugging (non-sensitive summary)
router.get("/auth/profile/:username", async (req, res) => {
  const { username } = req.params;
  const profile = await dataStore.getLoginProfile(username.toLowerCase());
  if (!profile) {
    return res.status(404).json({ error: "No baseline profile found for this user" });
  }
  return res.json({
    username: profile.username,
    knownIpsCount: profile.knownIps.length,
    knownUserAgentsCount: profile.knownUserAgents.length,
    failedAttempts: profile.failedAttempts,
    lastLoginAt: profile.lastLoginAt
  });
});

export default router;
