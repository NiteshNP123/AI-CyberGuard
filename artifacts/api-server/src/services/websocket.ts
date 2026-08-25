import { WebSocketServer, WebSocket } from "ws";
import type { Server as HttpServer } from "node:http";
import { logger } from "../lib/logger";

export interface SocketMessage {
  type: "EVENT_NEW" | "ALERT_NEW" | "INCIDENT_UPDATE" | "DASHBOARD_UPDATE" | "SYSTEM_HEALTH";
  payload: any;
  timestamp: string;
}

class WebSocketHub {
  private wss: WebSocketServer | null = null;
  private clients: Set<WebSocket> = new Set();

  init(server: HttpServer) {
    this.wss = new WebSocketServer({ server, path: "/ws" });

    this.wss.on("connection", (ws, req) => {
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
