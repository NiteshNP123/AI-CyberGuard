import { Router, type IRouter } from "express";
import { dataStore } from "../services/store";
import { wsHub } from "../services/websocket";

const router: IRouter = Router();

router.get("/alerts", async (_req, res) => {
  const alerts = await dataStore.getAlerts();
  return res.json(alerts);
});

router.patch("/alerts/:id/status", async (req, res) => {
  const { id } = req.params;
  const { status } = req.body || {};

  if (!["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"].includes(status)) {
    return res.status(400).json({ error: "Invalid status value" });
  }

  const updated = await dataStore.updateAlertStatus(id, status);
  if (!updated) {
    return res.status(404).json({ error: "Alert not found" });
  }

  wsHub.broadcast("ALERT_NEW", updated);
  return res.json(updated);
});

export default router;