import http from "node:http";
import app from "./app";
import { logger } from "./lib/logger";
import { wsHub } from "./services/websocket";

const rawPort = process.env["PORT"] || "5000";
const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

const server = http.createServer(app);

// Initialize WebSocket Hub
wsHub.init(server);

server.listen(port, () => {
  logger.info({ port }, "AI CyberGuard API & WebSocket Server listening");
});
