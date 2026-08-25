import { Router, type IRouter } from "express";
import { dataStore } from "../services/store";

const router: IRouter = Router();

router.get("/dashboard/summary", async (_req, res) => {
  const summary = await dataStore.getDashboardSummary();
  return res.json(summary);
});

router.get("/dashboard/events", async (req, res) => {
  const limit = req.query.limit ? Number(req.query.limit) : 20;
  const events = await dataStore.getRecentEvents(limit);
  return res.json(events);
});

export default router;