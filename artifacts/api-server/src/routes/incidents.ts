import { Router, type IRouter } from "express";
import { dataStore } from "../services/store";

const router: IRouter = Router();

router.get("/incidents", async (_req, res) => {
  const incidents = await dataStore.getIncidents();
  return res.json(incidents);
});

export default router;
