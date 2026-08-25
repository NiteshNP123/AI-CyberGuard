import { Router, type IRouter } from "express";
import { MLClient } from "../services/ml-client";
import { wsHub } from "../services/websocket";
import { db } from "@workspace/db";

const router: IRouter = Router();

router.get("/healthz", async (_req, res) => {
  const mlHealth = await MLClient.checkHealth();
  const dbHealth = db ? "connected" : "local_persistent_mode";
  const wsClients = wsHub.getClientCount();

  const isHealthy = mlHealth.status !== "offline";

  return res.json({
    status: isHealthy ? "healthy" : "degraded",
    timestamp: new Date().toISOString(),
    components: {
      backend: { status: "healthy", version: "1.0.0" },
      database: { status: "healthy", mode: dbHealth },
      mlEngine: mlHealth,
      networkIds: { status: "active", mode: "flow_telemetry_ready" },
      websocketHub: { status: "active", activeClients: wsClients }
    }
  });
});

export default router;
