import { Router, type IRouter } from "express";
import { dataStore } from "../services/store";
import { wsHub } from "../services/websocket";
import { requireWorkspaceToken } from "../lib/auth";
import { logger } from "../lib/logger";

const router: IRouter = Router();

/** GET /alerts — List all security alerts (newest first). */
router.get("/alerts", async (_req, res) => {
  const alerts = await dataStore.getAlerts();
  return res.json(alerts);
});

/** PATCH /alerts/:id/status — Update the status of a single alert. */
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

/**
 * POST /alerts/bulk-resolve
 * Marks all NEW and INVESTIGATING alerts as RESOLVED.
 * Does NOT delete them — they remain in the history.
 * Requires valid X-Workspace-Token header for authorization.
 */
router.post("/alerts/bulk-resolve", requireWorkspaceToken, async (_req, res) => {
  try {
    const count = await dataStore.bulkResolveAlerts();
    wsHub.broadcast("ALERTS_BULK_RESOLVED", { count });
    return res.json({ success: true, resolved: count, message: `${count} alert(s) marked as RESOLVED.` });
  } catch (err) {
    logger.error({ err }, "Bulk resolve failed");
    return res.status(500).json({ error: "Bulk resolve failed" });
  }
});

/**
 * DELETE /alerts
 * Permanently deletes ALL alerts from the database.
 * Requires valid X-Workspace-Token header for authorization.
 * Additionally requires X-Confirm-Clear: "yes-delete-all" as defense-in-depth.
 */
router.delete("/alerts", requireWorkspaceToken, async (req, res) => {
  const confirm = req.headers["x-confirm-clear"];
  if (confirm !== "yes-delete-all") {
    return res.status(400).json({
      error: "Confirmation required",
      message: "Send the header X-Confirm-Clear: yes-delete-all to confirm permanent deletion."
    });
  }
  try {
    const count = await dataStore.clearAllAlerts();
    wsHub.broadcast("ALERTS_CLEARED", { count });
    return res.json({ success: true, deleted: count, message: `${count} alert(s) permanently deleted.` });
  } catch (err) {
    logger.error({ err }, "Clear alerts failed");
    return res.status(500).json({ error: "Clear alerts failed" });
  }
});

export default router;