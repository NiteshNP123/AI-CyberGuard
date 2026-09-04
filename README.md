# AI CyberGuard — Real-Time AI Cybersecurity & Defensive SOC Platform

**AI CyberGuard** is a defensive Security Operations Center (SOC) and threat-intelligence platform powered by machine learning models, real-time WebSocket telemetry, and multi-vector correlation.

---

## 🌟 Key Capabilities & Status

| Vector / Module | Status | Methodology & Dataset |
|---|---|---|
| **URL Security Analyzer** | `IMPLEMENTED` | Scikit-learn Random Forest (26 lexical & domain structural features) trained on ISCX-URL2016, PhishTank, and Alexa/Tranco 1M. |
| **Phishing / Fraud NLP Detector** | `IMPLEMENTED` | Calibrated TF-IDF n-gram classifier + intent scoring (urgency, credential harvesting, financial coercion) trained on Nazario Phishing Corpus, SpamAssassin, and Enron. |
| **Network Flow IDS Monitor** | `IMPLEMENTED` | Multi-class Flow Classifier trained on CICIDS2017 & CSE-CIC-IDS2018 flow distributions (DoS/DDoS, Port Scan, Brute Force, Botnet C2). Ingestion ready for Zeek / Suricata flow logs. |
| **Threat Correlation Engine** | `IMPLEMENTED` | Multi-vector cross-telemetry correlation grouping linked attack signals across time windows into unified Incidents. |
| **Central Risk Engine (0–100)** | `IMPLEMENTED` | Calibrated scoring combining ML probabilities, heuristic evidence weights, and asset criticality. |
| **Real-Time SOC Telemetry** | `IMPLEMENTED` | WebSocket hub (`/ws`) dispatching live events, alerts, and incident updates to the React dashboard without page refresh. |
| **Defensive Wi-Fi Companion** | `IMPLEMENTED` | Local host companion (`scripts/wifi-companion.py`) querying native OS wireless APIs (`netsh wlan`) to evaluate wireless encryption posture. |
| **Static File Security Guard** | `IMPLEMENTED` | Shannon entropy calculation, MD5/SHA256 hashing, printable strings extraction, and PE header inspection. |
| **Defensive DNS Monitor** | `IMPLEMENTED` | Domain entropy calculation, DGA algorithmic detection, and DNS exfiltration/tunneling heuristic analysis. |
| **Identity & Login Anomaly** | `IMPLEMENTED` | Velocity checks, user baseline profiling, and brute-force attempt thresholding. |
| **Secret & Sensitive Data Leak Guard** | `IMPLEMENTED` | High-entropy credential scanner for AWS, GitHub PATs, Private Keys, JWTs, and database URLs with automated value masking. |
| **Privacy-First Chrome Extension** | `IMPLEMENTED` | Manifest V3 on-demand URL threat shield without background browsing history logging. |

---

## 🏗️ Architecture

```
                             ┌───────────────────────────────────┐
                             │       AI CYBERGUARD SOC UI        │
                             │       (React 19 / Tailwind)       │
                             └─────────────────▲─────────────────┘
                                               │
                                 (REST API + WebSocket Stream)
                                               │
                             ┌─────────────────▼─────────────────┐
                             │        Express API Server         │
                             │  (Risk Engine, Router, WS Hub)    │
                             └─▲───────────────▲───────────────▲─┘
                               │               │               │
            ┌──────────────────┴──┐     ┌──────┴─────────┐     └───┬────────────────────────┐
            │                     │     │                │         │                        │
  ┌─────────┴─────────┐ ┌─────────┴─────┴──┐ ┌───────────┴─────────┴──┐ ┌──────────────────┴───────────────┐
  │   URL Analyzer    │ │ Phishing/Fraud   │ │   Network IDS Monitor   │ │    Defensive System Modules       │
  │ (Lexical, Domain, │ │ Message Analyzer │ │ (Zeek/Suricata Flow Log │ │ (Local Wi-Fi Companion Agent,     │
  │ DNS, SSL signals) │ │ NLP Attributions │ │  Parser + Real Ingestion│ │  Static File Analyzer, DNS DGA,  │
  │                   │ │  Token Weights)  │ │  & IDS Telemetry)       │ │  Login Anomaly, Secret Leaker)    │
  └─────────┬─────────┘ └─────────┬────────┘ └───────────┬─────────────┘ └──────────────────┬────────────────┘
            │                     │                      │                                  │
            └─────────────────────┼──────────────────────┴──────────────────────────────────┘
                                  │
                                  ▼
                   ┌──────────────────────────────┐
                   │    Python AI/ML Service      │
                   │ (FastAPI Inference Engine)   │
                   │ • URL Classifier (RandomForest)
                   │ • NLP Phishing Model (TF-IDF)│
                   │ • Flow IDS Classifier (Flow) │
                   └──────────────┬───────────────┘
                                  │
                                  ▼
                   ┌──────────────────────────────┐
                   │  Central Risk Engine (0-100) │
                   │    & Threat Correlation      │
                   └──────────────┬───────────────┘
                                  │
                                  ▼
                   ┌──────────────────────────────────────────────────────────┐
                   │                Persistence (source of truth)          │
                   │                                                          │
                   │  ┌──────────────────────────┐  ┌────────────────────┐  │
                   │  │ PostgreSQL via Drizzle   │  │ Local JSON file    │  │
                   │  │ when DATABASE_URL is set │  │ store when         │  │
                   │  │                          │  │ DATABASE_URL is    │  │
                   │  │                          │  │ not set            │  │
                   │  └──────────────────────────┘  └────────────────────┘  │
                   │  (mutually exclusive — picked at API server startup)    │
                   └──────────────────────────────────────────────────────────┘
```

---

## ✅ Setup & Running

> All commands in this document are intended to be run from the **repository root**.
> Each long-running service runs in its **own terminal** so its logs can be observed independently.
>
> The application has three services. Which ones you actually need depends on what you are working on:
>
> | Service | Port | Required for… |
> |---|---|---|
> | **React / Vite frontend** | `5173` | Using the dashboard at all. |
> | **Express API + WebSocket server** | `5000` | The frontend talking to a backend (it does, for every page). |
> | **Python ML engine** | `8000` | ML-backed URL, message, and network-flow analysis. The API still starts without it — `/api/healthz` reports `mlEngine.status: "offline"` and the analyzers fall back to their heuristic path. |
> | **PostgreSQL** | `5432` | Only when you set `DATABASE_URL` to switch the API into PostgreSQL persistence mode. Without it, the API uses the local JSON file store. |
>
> A reasonable first run is **just the API + the frontend** in two terminals; bring up the ML engine in a third terminal whenever you want real ML inference.

### 1. Prerequisites

| Tool | Version | Notes |
|---|---|---|
| **Node.js** | `v20+` (Node `24` recommended) | Required by the API server and frontend (Vite 7). |
| **pnpm** | `v9+` / `v11+` | Workspace package manager. |
| **Python** | `3.10+` | Required by the ML engine, the Wi-Fi companion, and the optional PostgreSQL setup script. |
| **Python venv** | `venv` (stdlib) | The repo has a `.venv/` at the root; create / activate your own if you do not want to use it. |
| **PostgreSQL** | `17` (or compatible) | **Optional.** Required only if you want the PostgreSQL persistence mode. When `DATABASE_URL` is **not** set, the API server falls back to a local JSON file store. The two modes are mutually exclusive. |

### 2. Install dependencies

```bash
# Node workspace (api-server, ai-cyberguard frontend, libs, scripts)
pnpm install

# Python ML engine + companion dependencies
python -m pip install fastapi uvicorn scikit-learn joblib numpy pandas requests pydantic

# Optional: PostgreSQL setup script
python -m pip install psycopg2-binary
```

### 3. Train & export the offline ML models (one-time)

The ML engine loads pre-trained artifacts from `services/ml-engine/models/`. To regenerate them:

```bash
python services/ml-engine/train_url_model.py
python services/ml-engine/train_message_nlp.py
python services/ml-engine/train_network_ids.py
```

### 4. Environment configuration

The application reads the following environment variables. **Do not commit real secrets.**

| Variable | Required? | Purpose | Sensible local-dev value |
|---|---|---|---|
| `PORT` | No | Express API server port (default `5000`). | leave unset |
| `WORKSPACE_TOKEN` | **Yes** (for destructive operations) | Shared secret required by the server middleware for destructive endpoints (`POST /api/alerts/bulk-resolve`, `DELETE /api/alerts`, `POST /api/auth/event`). Fails closed (HTTP 503) if unset. | any long random string, e.g. `dev-local-token` |
| `VITE_WORKSPACE_TOKEN` | Only if the frontend calls destructive endpoints | Sent by the dashboard as the `X-Workspace-Token` header. **Must exactly match** `WORKSPACE_TOKEN`. | same value as `WORKSPACE_TOKEN` |
| `DATABASE_URL` | No | When set, switches the API server to PostgreSQL mode (Drizzle ORM). When unset, the local JSON file store is used. | `postgresql://cyberguard_user:cyberguard_app_secret@127.0.0.1:5432/cyberguard` (if you ran `scripts/setup-postgres.py`) |
| `ML_ENGINE_URL` | No | Override the URL the API uses to call the Python ML engine (default `http://127.0.0.1:8000`). | leave unset |
| `DASHBOARD_ORIGIN` | No | Adds an extra entry to the WebSocket Origin allowlist (alongside `http://127.0.0.1:5173`, `http://localhost:5173`, `http://127.0.0.1:5000`, `http://localhost:5000`). | leave unset unless you proxy the frontend through a custom origin |
| `BASE_PATH` | No | Vite base path for the frontend (default `/`). | leave unset |
| `NODE_ENV` | No | Set to `development` for the API `dev` script; otherwise the production-style `start` script is used. | leave unset |

### 5. Database setup (PostgreSQL mode — optional)

If you do **not** set `DATABASE_URL`, the API server uses the **local JSON file store** at
`artifacts/api-server/.data/cyberguard_store.json` as the source of truth. No database is required.

If you **do** want PostgreSQL mode:

```bash
# 1. Start a local PostgreSQL instance (e.g. service or docker) listening on :5432
# 2. Provision the database, app user, and schema:
python scripts/setup-postgres.py --password <your_postgres_superuser_password>

# The script prints the DATABASE_URL it expects, e.g.:
#   postgresql://cyberguard_user:cyberguard_app_secret@127.0.0.1:5432/cyberguard
# 3. Export it before starting the API server
# Unix / macOS / Linux:
export DATABASE_URL="postgresql://cyberguard_user:cyberguard_app_secret@127.0.0.1:5432/cyberguard"
# Windows PowerShell:
$env:DATABASE_URL = "postgresql://cyberguard_user:cyberguard_app_secret@127.0.0.1:5432/cyberguard"
```

The raw SQL migration also lives at `scripts/db-migrate.sql` and can be applied directly with `psql` if you prefer not to use the helper script.

> **In PostgreSQL mode the JSON file is neither read nor written** — the two stores are alternatives, not dual-write targets. In local JSON mode, the `.data/` directory and `cyberguard_store.json` are auto-created on first start.

### 6. Run the three services

Run each command in its own terminal. Leave the first two running while you develop.

**Terminal 1 — Python ML engine** (required for URL / message / network inference):

```bash
python -m uvicorn main:app --app-dir services/ml-engine --port 8000 --host 127.0.0.1
```

**Terminal 2 — Express API + WebSocket server** (port `5000`):

The two scripts in `artifacts/api-server/package.json` are:

- `start` — serves the **already-built** API (runs `node --enable-source-maps ./dist/index.mjs`). Use this when you have an existing build, e.g. after `pnpm run build` at the repo root, or to run a production-style local server.
- `dev` — runs `build` first and then `start`. Use this for normal local development so you always pick up the latest TypeScript source.

For normal local development:

```bash
pnpm -C artifacts/api-server run dev
```

To serve an already-built API (no rebuild):

```bash
pnpm -C artifacts/api-server run start
```

If you choose `start` without `dev`, make sure the build exists first:

```bash
pnpm -C artifacts/api-server run build
```

If you plan to use the destructive alert operations (Bulk resolve / Clear all) or the auth telemetry endpoint from the dashboard, also export:

```bash
# Unix / macOS / Linux:
export WORKSPACE_TOKEN="dev-local-token"
# Windows PowerShell:
$env:WORKSPACE_TOKEN = "dev-local-token"
```

**Terminal 3 — React / Vite frontend** (port `5173`):

```bash
pnpm -C artifacts/ai-cyberguard run dev
```

To call destructive operations from the dashboard, also export (must match the server's `WORKSPACE_TOKEN`):

```bash
# Unix / macOS / Linux:
export VITE_WORKSPACE_TOKEN="dev-local-token"
# Windows PowerShell:
$env:VITE_WORKSPACE_TOKEN = "dev-local-token"
```

### 7. Optional companion services

```bash
# Local Wi-Fi companion (queries netsh wlan on Windows; read-only diagnostic)
python scripts/wifi-companion.py

# Windows network flow sensor (Scapy + Npcap; pushes flow telemetry to /api/network/telemetry)
python scripts/network-sensor.py
```

### 8. Accessing the application

| Service | URL | Notes |
|---|---|---|
| Frontend (Vite dev) | <http://127.0.0.1:5173> | React dashboard. The dev server proxies `/api` and `/ws` to the API server. |
| API + WebSocket | <http://127.0.0.1:5000> | REST under `/api/*`, WebSocket on `/ws`. |
| ML engine | <http://127.0.0.1:8000> | FastAPI inference. Swagger UI on `/docs`. |

### 9. Verification / health checks

```bash
# API server + DB mode + ML engine reachability
curl http://127.0.0.1:5000/api/healthz

# ML engine directly
curl http://127.0.0.1:8000/health

# End-to-end integration test (uses port 5000 API; requires WORKSPACE_TOKEN for the auth test)
node scripts/test-integration.mjs
```

`GET /api/healthz` returns:

- `components.backend.status` — `healthy` when the API process is up.
- `components.database.mode` — `postgresql` or `local_persistent_mode`.
- `components.database.provider` — `PostgreSQL 17` or `JSON file store`.
- `components.mlEngine.status` — `healthy` if the ML engine answered `/health`, `degraded` on non-2xx, `offline` on network/timeout.
- `components.websocketHub.activeClients` — live count of connected dashboards.
- `components.networkSensor.status` — `ONLINE` / `STOPPED` (controlled by the in-process sensor gate at `POST /api/network/sensor/start` and `/stop`).

### 10. Common startup problems

| Symptom | Cause | Fix |
|---|---|---|
| `EADDRINUSE: address already in use :::5000` | Another process is bound to port 5000, or a previous API server is still running. | Stop the other process, or set `PORT=<other>` for the API server (and update `vite.config.ts` proxy + WebSocket `ALLOWED_ORIGINS` if you change it). |
| `AI CyberGuard API & WebSocket Server listening` then nothing on 5173 | Frontend dev server not started. | Start it in another terminal: `pnpm -C artifacts/ai-cyberguard run dev`. |
| `components.mlEngine.status = "offline"` in `/api/healthz` | ML engine is not running, or is on a different host/port. | Start `python -m uvicorn main:app --app-dir services/ml-engine --port 8000 --host 127.0.0.1`, or set `ML_ENGINE_URL` to wherever it is running. |
| `401 Unauthorized` on "Bulk resolve" / "Clear all" / `POST /api/auth/event` | `WORKSPACE_TOKEN` is unset on the server, or the `X-Workspace-Token` header from the client does not match. | Set `WORKSPACE_TOKEN` on the server and `VITE_WORKSPACE_TOKEN` on the frontend to the same value. |
| `503` "Server misconfiguration" on the same endpoints | `WORKSPACE_TOKEN` is not configured on the server. | Set it (e.g. `export WORKSPACE_TOKEN="dev-local-token"` on Unix, `$env:WORKSPACE_TOKEN="dev-local-token"` in PowerShell) in **the same terminal** before starting the API server. |
| Dashboard cannot connect to the WebSocket | Browser Origin is not in the allowlist (`http://127.0.0.1:5173`, `http://localhost:5173`, `http://127.0.0.1:5000`, `http://localhost:5000`). | Either use one of the standard origins or set `DASHBOARD_ORIGIN` before starting the API server. |
| `components.database.mode = "local_persistent_mode"` when I expected PostgreSQL | `DATABASE_URL` is not set in the API server's environment. | Set `DATABASE_URL` (e.g. `export DATABASE_URL=...` on Unix, `$env:DATABASE_URL=...` in PowerShell) in **the same terminal** that runs the API server. |
| Integration test reports `WORKSPACE_TOKEN` errors on the auth step | Test script defaults the header to `dev-token`. | Set `WORKSPACE_TOKEN=dev-token` before starting the API server (or set the same value in the script's environment). |

### 11. Development workflow

| Task | Command |
|---|---|
| Install everything | `pnpm install` |
| Typecheck the whole workspace | `pnpm run typecheck` |
| Build the whole workspace | `pnpm run build` |
| Build only the API server | `pnpm -C artifacts/api-server run build` |
| Build only the frontend | `pnpm -C artifacts/ai-cyberguard run build` |
| Run the API server (production-style) | `pnpm -C artifacts/api-server run start` |
| Run the API server in dev (build + start) | `pnpm -C artifacts/api-server run dev` |
| Run the frontend dev server | `pnpm -C artifacts/ai-cyberguard run dev` |
| Preview the built frontend | `pnpm -C artifacts/ai-cyberguard run serve` |
| Run the ML engine | `python -m uvicorn main:app --app-dir services/ml-engine --port 8000 --host 127.0.0.1` |
| Run the Wi-Fi companion | `python scripts/wifi-companion.py` |
| Run the integration test suite | `node scripts/test-integration.mjs` |
| Regenerate the API client (from OpenAPI) | `pnpm --filter @workspace/api-spec run codegen` |
| Push Drizzle schema to the DB (dev only) | `pnpm --filter @workspace/db run push` |

---

## 💾 Persistence Modes

Mode is picked at startup by `DATABASE_URL`: PostgreSQL when set, local JSON when not. **No dual-write.**

| Mode | Trigger | Source of truth | Useful when |
|---|---|---|---|
| **PostgreSQL** | `DATABASE_URL` is set | PostgreSQL via Drizzle | Production / multi-instance / shared persistence |
| **Local JSON** | `DATABASE_URL` is **not** set | `artifacts/api-server/.data/cyberguard_store.json` | Local dev, single-instance demo, no-DB setup |

The `GET /api/healthz` endpoint reports the active mode under `components.database.mode` (`postgresql` or `local_persistent_mode`) and `components.database.provider` (`PostgreSQL 17` or `JSON file store`).

> In DB mode the JSON file is neither read nor written; any pre-existing file is harmless.

---

## 🔒 Security Hardening & Defensive Principles

- **No Random/Simulated Data**: All dashboard metrics, scores, alerts, and distributions are dynamically computed from real persistent database records.
- **SSRF Defensive Guard**: URL analyzer blocks internal metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
- **Privacy-Preserving Extension**: Chrome Extension only inspects URLs when prompted by the user; does not track background browsing history.
- **Credential Masking**: Secret scanner masks discovered keys before storing event logs.
- **Destructive Endpoint Protection**: Bulk resolve, clear all alerts, and auth telemetry require the `X-Workspace-Token` header. Delete-all additionally requires `X-Confirm-Clear: yes-delete-all`.
- **WebSocket Origin Allowlist**: Browser WebSocket connections must come from an allowed origin; non-browser clients (no `Origin` header) are allowed for compatibility.
