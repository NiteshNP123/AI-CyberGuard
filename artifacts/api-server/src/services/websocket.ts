import { WebSocketServer, WebSocket } from "ws";
import type { Server as HttpServer } from "node:http";
import { logger } from "../lib/logger";

export interface SocketMessage {
  type: "EVENT_NEW" | "ALERT_NEW" | "INCIDENT_UPDATE" | "DASHBOARD_UPDATE" | "SYSTEM_HEALTH" | "SENSOR_STATUS" | "ALERTS_BULK_RESOLVED" | "ALERTS_CLEARED";
  payload: any;
  timestamp: string;
}

const ALLOWED_ORIGINS = new Set([
  "http://127.0.0.1:5173",
  "http://localhost:5173",
  "http://127.0.0.1:5000",
  "http://localhost:5000"
]);
if (process.env.DASHBOARD_ORIGIN) {
  ALLOWED_ORIGINS.add(process.env.DASHBOARD_ORIGIN);
}


class WebSocketHub {
  private wss: WebSocketServer | null = null;
  private clients: Set<WebSocket> = new Set();

  init(server: HttpServer) {
    this.wss = new WebSocketServer({ server, path: "/ws" });

    this.wss.on("connection", (ws, req) => {
      const origin = req.headers.origin;
      // Browser-sourced connections must have an allowed Origin. Non-browser/local
      // clients (no Origin header) are allowed for compatibility.
      if (origin && !ALLOWED_ORIGINS.has(origin)) {
        logger.warn({ origin, remoteAddress: req.socket.remoteAddress }, "Rejected WebSocket connection: disallowed Origin");
        ws.close(1008, "Origin not allowed");
        return;
      }

      this.clients.add(ws);
      logger.info({ remoteAddress: req.socket.remoteAddress, totalClients: this.clients.size }, "WebSocket client connected");

      // Send initial connection ack
      ws.send(JSON.stringify({
        type: "SYSTEM_HEALTH",
        payload: { status: "connected", message: "Real-time SOC stream active" },
        timestamp: new Date().toISOString()
      }));

      ws.on("message", (data) => {
        try {
          const parsed = JSON.parse(data.toString());
          if (parsed.type === "PING") {
            ws.send(JSON.stringify({ type: "PONG", timestamp: new Date().toISOString() }));
          }
        } catch {
          // ignore malformed ping
        }
      });

      ws.on("close", () => {
        this.clients.delete(ws);
        logger.info({ totalClients: this.clients.size }, "WebSocket client disconnected");
      });

      ws.on("error", (err) => {
        logger.error({ err }, "WebSocket client error");
        this.clients.delete(ws);
      });
    });

    logger.info("WebSocket Hub initialized on /ws");
  }

  broadcast(type: SocketMessage["type"], payload: any) {
    if (!this.wss) return;
    const msg: SocketMessage = {
      type,
      payload,
      timestamp: new Date().toISOString()
    };
    const json = JSON.stringify(msg);

    for (const client of this.clients) {
      if (client.readyState === WebSocket.OPEN) {
        try {
          client.send(json);
        } catch (err) {
          logger.error({ err }, "Error broadcasting to WS client");
        }
      }
    }
  }

  getClientCount(): number {
    return this.clients.size;
  }
}

export const wsHub = new WebSocketHub();
