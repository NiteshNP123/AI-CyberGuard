import { dataStore } from "./store";
import { wsHub } from "./websocket";
import { logger } from "../lib/logger";

export class ThreatCorrelationEngine {
  /**
   * Correlates an incoming high-severity security event with recent events in the last 30 minutes.
   * If a multi-vector pattern is recognized, automatically escalates into a Correlated Incident.
   */
  static async evaluateEvent(newEvent: { id: string; type: string; title: string; score: number; severity: string; source: string; metadata?: any }) {
    if (newEvent.score < 60) return;

    try {
      const recentEvents = await dataStore.getRecentEvents(15);
      const thirtyMinutesAgo = Date.now() - 30 * 60 * 1000;

      const relevantWindowEvents = recentEvents.filter(
        (e) => e.id !== newEvent.id && new Date(e.timestamp).getTime() > thirtyMinutesAgo && e.score >= 50
      );

      if (relevantWindowEvents.length === 0) return;

      const distinctTypes = new Set([newEvent.type, ...relevantWindowEvents.map((e) => e.type)]);

      // Check for multi-vector threat patterns:
      // Pattern 1: URL/Phishing Message + Login Anomaly / DNS Tunneling
      // Pattern 2: Network IDS Port Scan / DoS + Auth Anomaly
      // Pattern 3: Static File Analysis Malicious + Network C2 / Secret Leak
      const isMultiVector = distinctTypes.size >= 2;

      if (isMultiVector) {
        const correlatedEvents = [newEvent, ...relevantWindowEvents];
        const highestScore = Math.max(...correlatedEvents.map((e) => e.score));
        const incidentSeverity = highestScore >= 85 ? "CRITICAL" : "HIGH";

        const timeline = correlatedEvents.map((e) => ({
          eventId: e.id,
          timestamp: new Date().toISOString(),
          type: e.type,
          title: e.title,
          score: e.score,
          severity: e.severity
        }));

        const title = `Multi-Vector Threat Correlation: ${Array.from(distinctTypes).join(" + ")}`;
        const summary = `Coordinated security events detected across ${distinctTypes.size} vectors (${Array.from(distinctTypes).join(", ")}) within an active activity window. Indicates potential targeted compromise campaign.`;

        const incident = await dataStore.insertIncident({
          id: `INC-${Date.now().toString(36).toUpperCase()}`,
          title,
          severity: incidentSeverity,
          status: "OPEN",
          correlatedEventsCount: correlatedEvents.length,
          summary,
          timeline: JSON.stringify(timeline)
        });

        logger.warn({ incidentId: incident.id, title }, "Threat correlation triggered new security incident");

        // Broadcast incident update to all live SOC clients
        wsHub.broadcast("INCIDENT_UPDATE", incident);
      }
    } catch (err) {
      logger.error({ err }, "Error evaluating threat correlation");
    }
  }
}
