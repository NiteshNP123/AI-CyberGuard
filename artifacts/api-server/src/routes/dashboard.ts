import { Router, type IRouter } from "express";
import { GetRecentEventsQueryParams, GetDashboardSummaryResponse, GetRecentEventsResponse } from "@workspace/api-zod";

const router: IRouter = Router();

const events = [
  { id: "evt-1042", type: "URL_ANALYSIS", title: "Suspicious domain blocked", detail: "Login portal domain matched credential-harvesting signals", severity: "HIGH" as const, score: 78, timestamp: "2026-08-24T08:42:00.000Z", source: "URL Analyzer" },
  { id: "evt-1041", type: "LOGIN_ANOMALY", title: "Unusual sign-in detected", detail: "New device sign-in from an unfamiliar location", severity: "MEDIUM" as const, score: 56, timestamp: "2026-08-24T07:18:00.000Z", source: "Identity Guard" },
  { id: "evt-1040", type: "MESSAGE_ANALYSIS", title: "Phishing message quarantined", detail: "Urgency and credential-request language detected", severity: "CRITICAL" as const, score: 94, timestamp: "2026-08-24T06:54:00.000Z", source: "Message Analyzer" },
  { id: "evt-1039", type: "DNS", title: "DNS behavior within baseline", detail: "No tunneling indicators found in latest sample", severity: "LOW" as const, score: 12, timestamp: "2026-08-24T05:30:00.000Z", source: "DNS Monitor" },
];

router.get("/dashboard/summary", (_req, res) => {
  const data = {
    securityScore: 82,
    threatLevel: "HIGH" as const,
    critical: 2,
    high: 5,
    medium: 11,
    low: 8,
    totalScans: 1842,
    protectedAssets: 24,
    scoreTrend: [
      { label: "18 Aug", value: 74 }, { label: "19 Aug", value: 77 }, { label: "20 Aug", value: 75 },
      { label: "21 Aug", value: 80 }, { label: "22 Aug", value: 78 }, { label: "23 Aug", value: 81 }, { label: "24 Aug", value: 82 },
    ],
    distribution: [
      { label: "Critical", value: 2, color: "#ef5b68" }, { label: "High", value: 5, color: "#f39a4a" },
      { label: "Medium", value: 11, color: "#e6c354" }, { label: "Low", value: 8, color: "#49c59a" },
    ],
  };
  res.json(GetDashboardSummaryResponse.parse(data));
});

router.get("/dashboard/events", (req, res) => {
  const parsed = GetRecentEventsQueryParams.safeParse(req.query);
  const limit = parsed.success ? parsed.data.limit : 20;
  res.json(GetRecentEventsResponse.parse(events.slice(0, limit)));
});

export default router;