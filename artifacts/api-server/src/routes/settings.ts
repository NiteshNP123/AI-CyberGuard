import { Router, type IRouter } from "express";
import { dataStore } from "../services/store";

const router: IRouter = Router();

/**
 * GET /settings
 * Returns the current workspace and account settings
 */
router.get("/settings", async (_req, res) => {
  try {
    const settings = await dataStore.getSettings();
    return res.json(settings);
  } catch (err: any) {
    return res.status(500).json({ error: "Failed to fetch settings", details: err?.message });
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
  } catch (err: any) {
    return res.status(500).json({ error: "Failed to update settings", details: err?.message });
  }
};

router.put("/settings", updateHandler);
router.post("/settings", updateHandler);
router.patch("/settings", updateHandler);

export default router;
