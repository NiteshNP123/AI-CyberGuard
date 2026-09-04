import { Router, type IRouter } from "express";
import { dataStore } from "../services/store";
import { logger } from "../lib/logger";

const router: IRouter = Router();

const MAX_STRING_LEN = 200;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * GET /settings
 * Returns the current workspace and account settings
 */
router.get("/settings", async (_req, res) => {
  try {
    const settings = await dataStore.getSettings();
    return res.json(settings);
  } catch (err) {
    logger.error({ err }, "Failed to fetch settings");
    return res.status(500).json({ error: "Failed to fetch settings" });
  }
});

/**
 * PUT /settings, POST /settings, PATCH /settings
 * Updates workspace and account settings
 */
const updateHandler = async (req: any, res: any) => {
  try {
    const {
      name,
      workspaceName,
      notificationEmail,
      criticalAlerts,
      weeklyDigest,
      dataRetention,
      scanConfirmation
    } = req.body || {};

    if (typeof name === "string" && name.length > MAX_STRING_LEN) {
      return res.status(400).json({ error: "name exceeds maximum length" });
    }
    if (typeof workspaceName === "string" && workspaceName.length > MAX_STRING_LEN) {
      return res.status(400).json({ error: "workspaceName exceeds maximum length" });
    }
    if (typeof notificationEmail === "string") {
      if (notificationEmail.length > MAX_STRING_LEN) {
        return res.status(400).json({ error: "notificationEmail exceeds maximum length" });
      }
      if (!EMAIL_RE.test(notificationEmail)) {
        return res.status(400).json({ error: "notificationEmail is not a valid email address" });
      }
    }

    const updates: Record<string, any> = {};
    if (typeof name === "string") updates.name = name;
    if (typeof workspaceName === "string") updates.workspaceName = workspaceName;
    if (typeof notificationEmail === "string") updates.notificationEmail = notificationEmail;
    if (typeof criticalAlerts === "boolean") updates.criticalAlerts = criticalAlerts;
    if (typeof weeklyDigest === "boolean") updates.weeklyDigest = weeklyDigest;
    if (typeof dataRetention === "string") updates.dataRetention = dataRetention;
    if (typeof scanConfirmation === "boolean") updates.scanConfirmation = scanConfirmation;

    const saved = await dataStore.updateSettings(updates);
    return res.json(saved);
  } catch (err) {
    logger.error({ err }, "Failed to update settings");
    return res.status(500).json({ error: "Failed to update settings" });
  }
};

router.put("/settings", updateHandler);
router.post("/settings", updateHandler);
router.patch("/settings", updateHandler);

export default router;
