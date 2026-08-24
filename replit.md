# AI CyberGuard

AI CyberGuard is a defensive security operations center that scores user-provided URLs and messages, summarizes workspace risk, and tracks alerts.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `artifacts/ai-cyberguard` — React/Vite application and SOC dashboard routes.
- `artifacts/api-server/src/routes` — API handlers for dashboard summaries, alerts, and safe analyzers.
- `lib/api-spec/openapi.yaml` — source of truth for generated client and validation contracts.
- `attached_assets/image_1787558980758.png` — supplied work breakdown and architecture reference.

## Architecture decisions

- The first release uses deterministic, explainable defensive heuristics for URL and message analysis; it does not execute files or probe external systems.
- The web client consumes generated React Query hooks from the OpenAPI contract rather than calling the API directly with hand-written types.
- Dashboard and alert data are seeded in the API layer for the initial product slice; persistent PostgreSQL entities remain the next expansion step.

## Product

Users can review security posture, trend and threat distribution, inspect recent events, analyze URLs and messages for phishing signals, browse alerts, and manage workspace preferences.

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

_Populate as you build — sharp edges, "always run X before Y" rules._

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
