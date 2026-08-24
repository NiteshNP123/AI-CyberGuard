import { Router, type IRouter } from "express";
import { GetAlertsResponse } from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/alerts", (_req, res) => {
  const alerts = [
    { id: "ALT-2048", title: "Possible phishing-based account compromise", source: "Threat Correlation", severity: "CRITICAL" as const, score: 94, status: "NEW" as const, timestamp: "2026-08-24T06:54:00.000Z", description: "Suspicious message, high-risk URL, and abnormal login signals appeared in the same activity window." },
    { id: "ALT-2047", title: "Lookalike domain detected", source: "URL Analyzer", severity: "HIGH" as const, score: 78, status: "INVESTIGATING" as const, timestamp: "2026-08-24T08:42:00.000Z", description: "A domain contains structural indicators commonly associated with impersonation." },
    { id: "ALT-2046", title: "New device sign-in", source: "Identity Guard", severity: "MEDIUM" as const, score: 56, status: "RESOLVED" as const, timestamp: "2026-08-24T07:18:00.000Z", description: "A login from a new device was confirmed by the account owner." },
  ];
  res.json(GetAlertsResponse.parse(alerts));
});

export default router;