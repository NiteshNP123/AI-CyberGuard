import type { Request, Response, NextFunction } from "express";

/**
 * Lightweight authorization middleware for trusted endpoints.
 * Requires X-Workspace-Token header to match WORKSPACE_TOKEN environment variable.
 * Fails closed if WORKSPACE_TOKEN is not configured.
 */
export function requireWorkspaceToken(req: Request, res: Response, next: NextFunction): void {
  const expectedToken = process.env["WORKSPACE_TOKEN"];

  if (!expectedToken) {
    res.status(503).json({
      error: "Server misconfiguration",
      message: "WORKSPACE_TOKEN environment variable is not set. Protected operations are disabled."
    });
    return;
  }

  const providedToken = req.headers["x-workspace-token"];

  if (!providedToken || providedToken !== expectedToken) {
    res.status(401).json({
      error: "Unauthorized",
      message: "Valid X-Workspace-Token header required for this operation."
    });
    return;
  }

  next();
}
