import { Router, type IRouter } from "express";
import { MLClient } from "../services/ml-client";
import { wsHub } from "../services/websocket";
import { db } from "@workspace/db";
import { sensorState } from "./network";

const router: IRouter = Router();

router.get("/healthz", async (_req, res) => {
  const mlHealth = await MLClient.checkHealth();
  const dbMode = db ? "postgresql" : "local_persistent_mode";
  const dbProvider = db ? "PostgreSQL 17" : "JSON file store";
  const wsClients = wsHub.getClientCount();

  const isHealthy = mlHealth.status !== "offline";

  return res.json({
    status: isHealthy ? "healthy" : "degraded",
    timestamp: new Date().toISOString(),
    components: {
      backend: { status: "healthy", version: "1.0.0" },
      database: { status: "healthy", mode: "postgresql", provider: dbProvider },
      mlEngine: mlHealth,
      networkIds: { status: "active", mode: "flow_telemetry_ready" },
      networkSensor: {
        status: sensorState.enabled ? "ONLINE" : "STOPPED",
        enabled: sensorState.enabled,
        startedAt: sensorState.startedAt,
        stoppedAt: sensorState.stoppedAt,
        flowsIngested: sensorState.flowsIngested
      },
      websocketHub: { status: "active", activeClients: wsClients }
    }
  });
});

export default router;
