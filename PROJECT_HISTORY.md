# AI-CyberGuard Project History

This document preserves the complete development context for **AI-CyberGuard** up to the current clean baseline. It is intended as a single source of truth for resuming work in a fresh Claude session.

---

## Current Baseline

- **HEAD**: `c459377273ff9e912e3480147679d360b931a900`
- **Branch**: `main`
- **Last known-good committed state**: clean working tree, all six local commits are persisted in the local Git history.
- **Local vs. remote**: `main` is **6 commits ahead of** `origin/main`. Nothing has been pushed to GitHub.
- **Working tree**: must remain clean until the next phase of work begins.

The six local commits in chronological order (oldest → newest):

| # | SHA | Title |
|---|---|---|
| Batch 1 | `a4384cb` | fix: protect destructive alert operations |
| Batch 2 | `d9fc5a9` | fix: protect authentication telemetry endpoint |
| Batch 3 | `07dffa8` | fix: make local store mutations reliable |
| Batch 4 | `617b312` | fix: make persistence modes mutually exclusive |
| Batch 5 | `a8fa8d5` | fix: remove fabricated dashboard metrics |
| Batch 6 | `c459377` | fix: harden API error handling and WebSocket validation |

---

## Architecture / Project Context

**Stack (verified against the repo):**

- **Monorepo:** `pnpm` workspaces (`pnpm-workspace.yaml`).
- **Workspace packages:**
  - `artifacts/api-server` — `@workspace/api-server` (Express 5, pino, ws, CORS, drizzle-orm).
  - `artifacts/ai-cyberguard` — `@workspace/ai-cyberguard` (React 19, Vite 7, Tailwind v4, wouter, React Query, framer-motion, recharts, Radix UI, zod, sonner).
  - `artifacts/mockup-sandbox` — internal mockup workspace (not user-facing at runtime).
  - `lib/api-spec` — OpenAPI source of truth.
  - `lib/api-zod` — Zod schemas generated from OpenAPI.
  - `lib/api-client-react` — generated React Query hooks.
  - `lib/db` — Drizzle schema, table definitions, `db` client.
  - `scripts` — TypeScript / Node helper scripts and `*.py` companion agents.
- **TypeScript / Node:** TS `~5.9.3`, Node `v20+` (Node `24` recommended).
- **API server:** Express 5, pino + pino-http structured logging, WebSocket hub at `/ws`.
- **DB:** PostgreSQL 17 via Drizzle ORM, with a local JSON file fallback (`artifacts/api-server/.data/cyberguard_store.json`).
- **Frontend:** React 19, Vite 7, Tailwind v4 (oxide), wouter routing, TanStack Query for data, framer-motion for animation.
- **ML engine:** Python 3.10+ FastAPI service at `services/ml-engine/main.py`. Loads pre-trained `joblib` artifacts from `services/ml-engine/models/`.
- **Python companions:** `scripts/wifi-companion.py` (defensive Wi-Fi posture), `scripts/network-sensor.py` (Scapy + Npcap flow sensor).
- **Chrome extension:** `extensions/chrome/` (manifest v3, on-demand URL inspection only).

**Source-of-truth files for runtime startup:**

- `artifacts/api-server/package.json` — `build` / `start` / `dev` / `typecheck` scripts.
- `artifacts/ai-cyberguard/package.json` — `dev` / `build` / `serve` / `typecheck` scripts.
- `artifacts/ai-cyberguard/vite.config.ts` — dev proxy `/api` and `/ws` to `http://127.0.0.1:5000`.
- `artifacts/api-server/src/index.ts` — API server bootstrap on `PORT` (default `5000`).
- `artifacts/api-server/src/services/websocket.ts` — WebSocket Origin allowlist.
- `artifacts/api-server/src/services/store.ts` — persistence layer (DB or local JSON).
- `artifacts/api-server/src/lib/auth.ts` — `requireWorkspaceToken` middleware.
- `services/ml-engine/main.py` — FastAPI app + `/health` + ML endpoints.
- `scripts/setup-postgres.py` + `scripts/db-migrate.sql` — PostgreSQL provisioning.

---

## Batch 1 — `a4384cb` — fix: protect destructive alert operations

**What was changed:**

- Added an in-file `requireWorkspaceToken` middleware inside `artifacts/api-server/src/routes/alerts.ts` that requires the `X-Workspace-Token` request header to match the server's `WORKSPACE_TOKEN` env var.
- Applied that middleware to two destructive routes:
  - `POST /api/alerts/bulk-resolve` (resolves all `NEW` / `INVESTIGATING` alerts).
  - `DELETE /api/alerts` (permanently deletes every alert).
- Kept the existing `X-Confirm-Clear: yes-delete-all` defense-in-depth header on `DELETE /api/alerts` alongside the new token check.
- Updated the dashboard (`artifacts/ai-cyberguard/src/pages/alerts.tsx`) to send the `X-Workspace-Token` header on the two destructive operations, reading it from `import.meta.env.VITE_WORKSPACE_TOKEN`.
- Updated the README to document `WORKSPACE_TOKEN` (server) and `VITE_WORKSPACE_TOKEN` (frontend), and the requirement that the two values match.

**Why it was changed:**

- Destructive operations must not be triggerable by a misconfigured or unauthenticated client. Failing closed when the token is unset prevents accidentally exposing bulk-resolve / clear-all on a freshly deployed server.

**Important security/functionality behavior:**

- The middleware returns `503` when `WORKSPACE_TOKEN` is unset, with the message *"Server misconfiguration: WORKSPACE_TOKEN environment variable is not set. Destructive operations are disabled."*
- It returns `401` when the header is missing or does not match.
- Non-destructive routes (e.g. `GET /api/alerts`, `PATCH /api/alerts/:id/status`) were **not** changed.

**Validation performed:**

- Manual startup of API + frontend, then a successful Bulk resolve and a successful Clear all when the token matched.
- Manual verification of `401` when the frontend token is missing or wrong.

---

## Batch 2 — `d9fc5a9` — fix: protect authentication telemetry endpoint

**What was changed:**

- Lifted the `requireWorkspaceToken` middleware out of `alerts.ts` into a shared module at `artifacts/api-server/src/lib/auth.ts`.
- Removed the in-file copy from `alerts.ts` and imported from the shared module.
- Applied the middleware to `POST /api/auth/event` in `artifacts/api-server/src/routes/auth.ts`, the login-anomaly telemetry ingestion endpoint.
- Updated `scripts/test-integration.mjs` to send `X-Workspace-Token: process.env.WORKSPACE_TOKEN || 'dev-token'` on the auth event test.

**Why it was changed:**

- The same token-gate used for destructive alert operations is also appropriate for the auth telemetry endpoint: it lets a system ingest login anomalies without exposing an open cross-origin write surface. Sharing the middleware prevents drift if the auth logic is updated.

**Route protection summary (after Batch 2):**

- `POST /api/alerts/bulk-resolve` — `requireWorkspaceToken`.
- `DELETE /api/alerts` — `requireWorkspaceToken` + `X-Confirm-Clear: yes-delete-all`.
- `POST /api/auth/event` — `requireWorkspaceToken`.

**Validation performed:**

- The integration test (`node scripts/test-integration.mjs`) exercises the auth event endpoint with the token header. Re-running the test without `WORKSPACE_TOKEN` configured on the server now produces a `503`.

---

## Batch 3 — `07dffa8` — fix: make local store mutations reliable

**What was changed (in `artifacts/api-server/src/services/store.ts`):**

- Introduced a `writeQueue: Promise<void>` on the `DataStoreService` and a private `serialize<T>(fn)` helper. Every mutation (`insertSecurityEvent`, `insertAlert`, `updateAlertStatus`, `bulkResolveAlerts`, `clearAllAlerts`, `insertUrlScan`, `insertMessageScan`, `insertNetworkEvent`, `insertDnsEvent`, `insertLoginEvent`, `insertFileScan`, `upsertLoginProfile`, `updateSettings`, `insertIncident`, `updateIncidentStatus`) is now wrapped in `serialize(...)` so writes cannot interleave.
- `persistLocalStore()` now writes the JSON to a unique temp file (`.tmp.<pid>.<ts>`) and then `fs.renameSync` it over the live `cyberguard_store.json`. This is the standard "write-temp-then-rename" atomicity pattern on POSIX/Windows.
- The JSON load path is wrapped in `try { JSON.parse } catch { ... }`:
  - On a parse failure, the corrupted file is renamed to `cyberguard_store.json.corrupted.<unix-ms>` (preserving it for manual recovery), and the in-memory state falls back to defaults.
  - If the rename itself fails, the process logs and continues with defaults.

**Why it was changed:**

- Earlier, mutations could race and the JSON file could be partially written if the process crashed mid-write, leaving the next start unable to parse the file. The serialized queue + atomic rename make the local store behave predictably under load and survive crashes.

**Important implementation considerations discovered during review:**

- `process.cwd()` is used to resolve `.data/` — keep starting the API server from the `artifacts/api-server` package directory (or via `pnpm -C artifacts/api-server run start`, which sets `cwd` to that package). If you `cd` to a different directory before starting, the data file will be created in that directory.
- The `writeQueue` only serializes calls **inside one process**. Two API server processes pointed at the same JSON file will still race; the local store is single-instance by design. PostgreSQL mode is the multi-instance alternative.
- Atomic rename on Windows is supported by `fs.renameSync` (it falls back to `MoveFileEx` semantics), but it can fail if another process has the file open for reading without sharing. The serialization queue largely prevents this in practice.

**Validation performed:**

- Rapid-fire manual scans and dashboard refreshes against the local JSON store. No torn or partial JSON files observed in `.data/`.
- Forced corruption test: hand-edited the JSON file to invalid syntax, restarted, and confirmed the corrupted file was preserved with the `.corrupted.<ts>` suffix and the server started cleanly with default state.

---

## Batch 4 — `617b312` — fix: make persistence modes mutually exclusive

**What was changed:**

- The local JSON file path and PostgreSQL path in `artifacts/api-server/src/services/store.ts` are now strictly **either/or**:
  - `initLocalStore()` returns early if `db` (the Drizzle client) is set, so the JSON file is never read in DB mode.
  - Every mutation checks `if (db) { ...; return; }` before touching `localState`; there is no longer a "write to DB, fall back to JSON" path.
  - Removed the `try { db.insert } catch { console.warn("DB insert error, falling back to store") }` fallback in Batch 4 — DB errors now surface to the caller.
- `routes/health.ts` now reports the actual mode from `db ? "postgresql" : "local_persistent_mode"` (previously the response was hard-coded to `postgresql` regardless of whether `DATABASE_URL` was set).
- `README.md` was updated with a dedicated "Persistence Modes" section that documents the mutual exclusivity and the active-mode reporting in `/api/healthz`.

**Why it was changed:**

- Dual-write is dangerous: a partial failure between DB and JSON can leave the two stores inconsistent, and the dashboard / correlation engine has to guess which one is the source of truth. Picking one store at startup (controlled by the presence of `DATABASE_URL`) makes the data model single-sourced and the failure modes obvious.

**`/api/healthz` mode reporting (after Batch 4):**

- `components.database.mode` — `"postgresql"` when `DATABASE_URL` is set, `"local_persistent_mode"` when not.
- `components.database.provider` — `"PostgreSQL 17"` or `"JSON file store"`.

**Integration testing performed:**

- With `DATABASE_URL` set: ran the integration test, observed `mode: "postgresql"`, `provider: "PostgreSQL 17"`. No writes to `cyberguard_store.json` observed.
- With `DATABASE_URL` unset: ran the integration test, observed `mode: "local_persistent_mode"`, `provider: "JSON file store"`. Inspected `artifacts/api-server/.data/cyberguard_store.json` and confirmed the new events / scans were persisted.

---

## Batch 5 — `a8fa8d5` — fix: remove fabricated dashboard metrics

**What was changed:**

- The dashboard summary backend (`dataStore.getDashboardSummary` in `services/store.ts`) no longer synthesizes:
  - The `protectedAssets` field — derived from a formula `Math.max(1, Math.min(50, 12 + Math.floor(totalScans / 3)))` — was removed entirely.
  - The `scoreTrend` field — previously hard-coded to a 7-day fabricated trajectory `["18 Aug", ..., "24 Aug"]` with values generated from `securityScore + dayFactor` — is now returned as an empty array (real history can be wired in later from `security_events.timestamp` if desired).
  - The "low" alert bucket — previously inflated to `Math.max(lowAlerts, totalScans ? Math.max(1, totalScans - criticalAlerts - highAlerts - mediumAlerts) : 0)` — is now the literal count of low-severity alerts.
- The frontend `artifacts/ai-cyberguard/src/pages/dashboard.tsx` was updated:
  - The "Protected assets" panel was removed.
  - The conic distribution chart's center label changed from "total scans" to "active alerts" to match what the chart actually shows.
  - The grid was rebalanced from `lg:grid-cols-[1.3fr_1fr_1fr]` to `lg:grid-cols-[1.25fr_1fr]` since one panel was removed.
  - The fallback / empty `summary` no longer references `protectedAssets`.
- The OpenAPI spec, the generated Zod schema, and the generated React Query types were updated together so the contract stays consistent (`lib/api-spec/openapi.yaml`, `lib/api-zod/src/generated/api.ts`, `lib/api-zod/src/generated/types/dashboardSummary.ts`, `lib/api-client-react/src/generated/api.schemas.ts`).

**Why it was changed:**

- A defensive SOC product must not display synthesized data as if it were measured. The previous behavior was easy to mistake for real asset-coverage and real history, which is exactly the kind of fabricated telemetry a security platform should not ship.

**Validation performed:**

- Inspected `/api/dashboard/summary` directly with `curl`. `protectedAssets` is absent, `scoreTrend` is `[]`, `low` matches the actual count of low-severity alerts.
- Confirmed the dashboard renders without TypeScript or runtime errors after the panel was removed.

---

## Batch 6 — `c459377` — fix: harden API error handling and WebSocket validation

**What was changed:**

**`artifacts/api-server/src/routes/alerts.ts`:**

- Replaced `catch (err: any) { return res.status(500).json({ error, details: err?.message }) }` with `catch (err) { logger.error({ err }, "..."); return res.status(500).json({ error }) }` for both `bulk-resolve` and `clear-all`. The raw `err.message` is no longer leaked to the client; it is logged via pino instead.

**`artifacts/api-server/src/routes/settings.ts`:**

- Same error-message leakage fix on `GET /settings` and on the shared `updateHandler` (`PUT` / `POST` / `PATCH /settings`).
- Added input validation on the update path:
  - `name` and `workspaceName` must not exceed 200 characters.
  - `notificationEmail` must not exceed 200 characters and must match `^[^\s@]+@[^\s@]+\.[^\s@]+$`.
  - Other fields (`criticalAlerts`, `weeklyDigest`, `dataRetention`, `scanConfirmation`) keep their existing type checks (`typeof === "boolean"` / `typeof === "string"`).

**`artifacts/api-server/src/services/websocket.ts`:**

- Introduced an `ALLOWED_ORIGINS` allowlist:
  - `http://127.0.0.1:5173`
  - `http://localhost:5173`
  - `http://127.0.0.1:5000`
  - `http://localhost:5000`
  - Plus any value from `process.env.DASHBOARD_ORIGIN` (single string).
- On `connection`, the server reads `req.headers.origin`. If it is present and not in the allowlist, the server logs a warning and closes the socket with code `1008` and reason "Origin not allowed". Connections with no `Origin` header (e.g. local non-browser clients) are still accepted for compatibility.

**Why it was changed:**

- Unhandled error `.message` strings can leak stack internals, file paths, query text, or third-party library details to anonymous clients. Logging them server-side and returning a generic error message is the standard hardening pattern.
- The settings endpoint is one of the few write paths that can be hit from the dashboard with arbitrary user-supplied data. A 200-character cap and an email regex are cheap defenses against overflow and malformed input.
- The WebSocket hub at `/ws` was open to any browser tab that knew the address. Adding an Origin allowlist makes cross-site hijack attempts fail at the transport layer.

**Validation performed:**

- Manually triggered a `DELETE /api/alerts` with the JSON file deliberately read-only; the response now returns `{"error": "Clear alerts failed"}` (no `details`), while the pino log shows the underlying `EACCES` error.
- Manually `PUT /api/settings` with `notificationEmail: "not-an-email"` — receives `400 {"error": "notificationEmail is not a valid email address"}`.
- Connected a browser tab from a non-allowed origin to `ws://127.0.0.1:5000/ws`; the connection was closed with code `1008` and the server logged `Rejected WebSocket connection: disallowed Origin`.
- Connected a browser tab from `http://127.0.0.1:5173` to `ws://127.0.0.1:5000/ws`; the connection succeeded and the dashboard received the `SYSTEM_HEALTH` ack.

---

## Manual Testing Before UI Work

This section records the application workflows that were exercised against the Batch 6 baseline prior to the discarded UI experiments. To keep the record honest, each item is tagged:

- **Implementation** — the underlying code/contract change is visible in the diff for that batch.
- **Automated verification** — covered by `scripts/test-integration.mjs` (the only automated end-to-end test in the repo) or directly asserted by reading a code path.
- **Manual testing** — driven through the dashboard UI or via `curl` against a running server by the developer during the Batch 6 work.

What is **not** asserted here: exhaustive coverage of every UI screen, performance characteristics, multi-instance behaviour, or any workflow that was not part of the Batch 6 fix scope.

### Application startup

- **Implementation:** the three services are independently bootable; the API server has no required startup dependency on the frontend or the ML engine (Batch 4+ design).
- **Manual testing:** the three services were started in three terminals in the order ML engine → API → frontend. The API logged `AI CyberGuard API & WebSocket Server listening` on its configured port; the frontend reported the Vite dev server URL; the ML engine reported model artifacts loaded.
- **Automated verification:** `GET /api/healthz` exposes `components.backend`, `components.database.{mode,provider}`, `components.mlEngine.status`, and `components.websocketHub.activeClients` (see `artifacts/api-server/src/routes/health.ts`); the shape of that response is fixed by the route handler.

### Dashboard

- **Implementation:** Batch 5 removed the fabricated `protectedAssets` and the fabricated `scoreTrend`; the `dataStore.getDashboardSummary` shape is now `{ securityScore, threatLevel, critical, high, medium, low, totalScans, scoreTrend, distribution }`.
- **Automated verification:** the OpenAPI / Zod / React-Query generated contracts no longer reference `protectedAssets` (Batch 5 changed those together with the implementation).
- **Manual testing:** `GET /api/dashboard/summary` was inspected via `curl` and the values were checked against the underlying events/alerts/scans tables. The Batch 5 commit message records the manual check; the broader dashboard rendering was visually inspected in the browser during the Batch 6 work and no errors were observed.

### URL Analyzer

- **Implementation:** the analyzer lives at `POST /api/analysis/url` (`artifacts/api-server/src/routes/analysis.ts`); it SSRF-blocks `169.254.169.254` and `metadata.google.internal`, and otherwise calls `MLClient.predictUrl` with a heuristic fallback.
- **Automated verification:** `scripts/test-integration.mjs` step 2 issues a POST against `/api/analysis/url` with a deliberately malicious URL and prints the returned classification, risk score, confidence, and indicators.
- **Manual testing:** the malicious URL case was run interactively during Batch 6 and produced the expected non-zero risk score. The SSRF guard was observed to return `400` for `http://169.254.169.254/...` in the same session.

### Message Analyzer

- **Implementation:** `POST /api/analysis/message` calls `MLClient.predictMessage` (TF-IDF + INTENT_RULES scoring).
- **Automated verification:** `scripts/test-integration.mjs` step 3 issues a POST against `/api/analysis/message` with a coercive message and prints the returned classification, signals, and risk score.
- **Manual testing:** the integration test prompt was re-run interactively during Batch 6 with the same coercion template; the response was inspected via `curl`.

### Alerts

- **Implementation:** `GET /api/alerts`, `PATCH /api/alerts/:id/status`, `POST /api/alerts/bulk-resolve`, and `DELETE /api/alerts` are all in `artifacts/api-server/src/routes/alerts.ts`. Batches 1 and 2 added the `requireWorkspaceToken` middleware to the destructive routes and Batch 6 removed the `err.message` leak from the catch blocks.
- **Automated verification:** `scripts/test-integration.mjs` step 10 lists alerts and then PATCHes a single alert's status.
- **Manual testing:** during Batch 1 a successful Bulk resolve and a successful Clear all were performed from the dashboard with matching tokens. During Batch 2 the auth route protection was added. During Batch 6 the dashboard was opened with no token configured and the destructive buttons produced the expected `401` / `503`.

### Settings

- **Implementation:** `GET /api/settings` and the shared `updateHandler` (PUT/POST/PATCH `/api/settings`) are in `artifacts/api-server/src/routes/settings.ts`. Batch 6 added the 200-character cap and the email regex, and removed the `err.message` leak.
- **Manual testing:** the settings page was opened in the browser; the displayed defaults matched the `DEFAULT_SETTINGS` in `services/store.ts` (`Avery Mitchell` / `Northstar Studio` / `avery@northstar.studio`). A `PUT` with valid values was issued via the dashboard and the page reflected the update on next render. A `PUT` with `notificationEmail: "not-an-email"` was issued via `curl` and returned the expected `400`.

### Network sensor controls / status

- **Implementation:** the in-process sensor gate lives in `artifacts/api-server/src/routes/network.ts`. `GET /network/sensor/status`, `POST /network/sensor/start`, `POST /network/sensor/stop`, and `POST /network/telemetry` are all defined there.
- **Manual testing:** during Batch 6 the start / stop endpoints were exercised via `curl` and the gate was observed to flip `enabled: true ↔ false`. After `stop`, a `POST /network/telemetry` returned `503 "Network sensor is stopped"`; after `start`, a DoS-profile flow returned `attackClass: "DOS_DDOS"`, `severity: "CRITICAL"`.

### WebSocket behavior

- **Implementation:** the hub is at `path: "/ws"` in `services/websocket.ts`; the Origin allowlist is the four default URLs plus `DASHBOARD_ORIGIN` (Batch 6). The hub broadcasts `EVENT_NEW`, `ALERT_NEW`, `INCIDENT_UPDATE`, `DASHBOARD_UPDATE`, `SYSTEM_HEALTH`, `SENSOR_STATUS`, `ALERTS_BULK_RESOLVED`, `ALERTS_CLEARED`.
- **Manual testing:** a browser tab on `http://127.0.0.1:5173` connected successfully and received the `SYSTEM_HEALTH` ack. A browser tab on a non-allowed origin was rejected with close code `1008` and the server logged the rejection (Batch 6 validation).
- **Note on dashboard-side broadcast reflection:** the broadcast *types* are sent by the API; whether the React dashboard currently auto-refreshes its lists in response to a particular event is a UI concern that was not part of the Batch 6 diff and is therefore **not** asserted here.

### ML engine startup / usage

- **Implementation:** `services/ml-engine/main.py` loads `url_model.joblib`, `message_nlp_model.joblib`, and `network_ids_model.joblib` from `services/ml-engine/models/` at import time and exposes `GET /health` plus the three `/api/ml/*/predict` routes.
- **Manual testing:** `python -m uvicorn main:app --app-dir services/ml-engine --port 8000 --host 127.0.0.1` started cleanly with all three model artifacts loaded. `GET /health` returned `status: "healthy"` and per-model `loaded: true` flags. A network flow whose feature vector matched the DoS profile produced the expected attack class via the ML model (not the heuristic fallback).

---

## First-Run Onboarding Experiment — DISCARDED

**Status: DISCARDED. Do not assume this exists in the current codebase.**

After Batch 6 we briefly experimented with a first-run onboarding gate that asked the user to provide:

- **Name** (`name`)
- **Workspace name** (`workspaceName`)
- **Email** (`notificationEmail`)

The values were persisted through `PUT /api/settings` (the standard workspace-settings endpoint), not through a new signup/login route. The experiment intentionally was **not** a signup or login flow — there was no password, no session, no auth token, no cookie.

The onboarding gate:

- Did **not** use `localStorage`, `sessionStorage`, or cookies.
- Did **not** introduce any new server routes, tables, or columns.
- Used the existing `/api/settings` write path and the existing `SettingsRecord` shape.

It was manually tested against the Batch 6 backend and worked end-to-end.

**It was deliberately discarded** when the workflow was reset to `c459377`. It is **not** part of the current baseline, and a future Claude session must not assume it currently exists or that `/api/settings` carries onboarding-specific logic.

---

## Frontend Redesign Experiments — DISCARDED

**Status: DISCARDED. Do not assume any of this exists in the current codebase.**

After Batch 6 there were **multiple** frontend redesign experiments that were rejected and then removed. They included, in no particular order:

- Typography and spacing cleanup.
- A dark visual system attempt.
- A dashboard redesign.
- A floating top navigation.
- A glass / frosted-treatment treatment.
- Animation experiments.
- Playwright-driven visual inspection of the running dashboard.

These experiments were rolled back with:

```bash
git reset --hard c459377
git clean -fd
```

Therefore:

- **None** of those rejected UI changes are part of the current codebase.
- A future Claude session must **not** assume the existence of any redesigned layout, dark-mode tokens, floating nav, glassmorphism, or animation system. Treat the frontend as the Batch 6 baseline only.
- Any screenshots, mockups, or artifacts generated during those experiments were deleted in the reset.

---

## Important Lessons / Constraints for Future Work

1. **The application was already functionally working at Batch 6.** The three services start cleanly, the dashboard renders real data, all analyzers (URL, message, file, DNS, secrets, network) return real ML or heuristic results, alerts can be triaged, settings persist, and the WebSocket hub streams events.
2. **Future UI work must preserve functionality.** Do not change API contracts, persistence semantics, auth middleware, or WebSocket behavior as a side effect of a visual redesign.
3. **Frontend redesign is intended to be a real visual redesign, not merely typography/spacing cleanup.** The discarded experiments are not a starting point.
4. **Desired visual direction (carried over from the discarded experiments):**
   - Dark aesthetic.
   - Premium, visually appealing, distinctive.
   - Sophisticated color theory (not stock-tailwind, not neon).
   - Strong typography.
   - Intentional whitespace.
   - Floating / glass navigation is one possible direction, not a requirement.
   - Smooth, polished animations and transitions.
   - **Not** generic AI-dashboard aesthetics.
   - **Not** cyberpunk / neon overload.
5. **Visual redesign must be validated in the actual browser.** Headless inspection is not a substitute for opening the dashboard and walking through each page.
6. **No commits or pushes until manual testing and final approval.** All work in this next phase is local until the user signs off.
7. **Do not modify backend / API / security / persistence logic during frontend redesign** unless a genuine frontend-integration issue requires it. If such a change is unavoidable, call it out explicitly before making it.
8. **Do not perform destructive process management.** Do not kill unrelated processes, do not wipe persisted data, do not reset `.data/cyberguard_store.json` or any DB rows merely to "see what an empty state looks like". Use the existing UI controls (sensor start/stop, alert resolve, etc.) to observe state changes.
9. **Do not reset or delete persisted data for visual inspection.** Persisted data is part of the test surface. If you need a clean visual, ask the user how to proceed.
10. **Keep Git history protected.** All work must continue to be diff-reviewable, reversible, and uncommitted until the user approves.
11. **The developer / user controls the service terminals themselves.** During development and testing, you (the human) start and stop the three service terminals (API, frontend, ML engine) by hand as needed — Claude must not start, restart, or stop them on the user's behalf, and must not assume any service is currently running unless the user has just confirmed it. This is a workflow instruction, not a security boundary; it exists so logs and process state stay predictable between turns.

---

## Git / Push State

- **Six local commits exist** (`a4384cb` … `c459377`) on `main`.
- **None have been pushed** to GitHub.
- `origin/main` is **6 commits behind** local `main`.
- The final push is **intentionally postponed** until all manual testing and the next phase of UI work is complete and approved.
- `git status` is **clean** at the current baseline.

---

## Current Next Step

The next phase is a **fresh, controlled frontend redesign starting from `c459377`**.

A future Claude session must:

- Treat the frontend as the Batch 6 baseline, full stop.
- **Not** claim that any onboarding flow, dark visual system, floating nav, glass treatment, or animation system currently exists.
- Begin by asking the user which services they currently have running (API, frontend, ML engine) before any UI work — the user starts and stops those terminals themselves; Claude does not.
- Begin with the README's "Setup & Running" workflow to bring the three services up before any UI work, if the user asks for it.
- Apply the lessons and constraints in the section above.
- Stop and surface anything that conflicts with this document.
