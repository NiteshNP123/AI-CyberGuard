-- AI CyberGuard PostgreSQL Schema Migration
-- Run this after creating the 'cyberguard' database:
--   psql -U postgres -c "CREATE DATABASE cyberguard;"
--   psql -U postgres -d cyberguard -f scripts/db-migrate.sql

CREATE TABLE IF NOT EXISTS security_events (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail      TEXT NOT NULL,
    severity    TEXT NOT NULL,
    score       INTEGER NOT NULL,
    source      TEXT NOT NULL,
    metadata    TEXT,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS url_scans (
    id              TEXT PRIMARY KEY,
    url             TEXT NOT NULL,
    domain          TEXT NOT NULL,
    classification  TEXT NOT NULL,
    risk_score      INTEGER NOT NULL,
    confidence      INTEGER NOT NULL,
    summary         TEXT NOT NULL,
    indicators      TEXT NOT NULL,
    signals         TEXT NOT NULL,
    ml_features     TEXT,
    recommendation  TEXT NOT NULL,
    analyzed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS message_scans (
    id                  TEXT PRIMARY KEY,
    message             TEXT NOT NULL,
    classification      TEXT NOT NULL,
    risk_score          INTEGER NOT NULL,
    confidence          INTEGER NOT NULL,
    summary             TEXT NOT NULL,
    indicators          TEXT NOT NULL,
    signals             TEXT NOT NULL,
    token_attributions  TEXT,
    recommendation      TEXT NOT NULL,
    analyzed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS network_events (
    id              TEXT PRIMARY KEY,
    src_ip          TEXT NOT NULL,
    dst_ip          TEXT NOT NULL,
    src_port        INTEGER NOT NULL,
    dst_port        INTEGER NOT NULL,
    protocol        TEXT NOT NULL,
    flow_duration   INTEGER NOT NULL,
    packet_count    INTEGER NOT NULL,
    byte_count      INTEGER NOT NULL,
    attack_class    TEXT NOT NULL,
    severity        TEXT NOT NULL,
    risk_score      INTEGER NOT NULL,
    confidence      INTEGER NOT NULL,
    flow_features   TEXT,
    raw_telemetry   TEXT,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dns_events (
    id              TEXT PRIMARY KEY,
    query_domain    TEXT NOT NULL,
    query_type      TEXT NOT NULL,
    entropy         INTEGER NOT NULL,
    is_dga          BOOLEAN NOT NULL DEFAULT FALSE,
    is_tunneling    BOOLEAN NOT NULL DEFAULT FALSE,
    severity        TEXT NOT NULL,
    risk_score      INTEGER NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS login_events (
    id              TEXT PRIMARY KEY,
    user_id         TEXT,
    username        TEXT NOT NULL,
    ip_address      TEXT NOT NULL,
    user_agent      TEXT NOT NULL,
    status          TEXT NOT NULL,
    is_anomaly      BOOLEAN NOT NULL DEFAULT FALSE,
    anomaly_reason  TEXT,
    risk_score      INTEGER NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Persistent behavioral login baseline profiles (survives server restarts)
CREATE TABLE IF NOT EXISTS login_profiles (
    username            TEXT PRIMARY KEY,
    known_ips           TEXT NOT NULL DEFAULT '[]',
    known_user_agents   TEXT NOT NULL DEFAULT '[]',
    failed_attempts     INTEGER NOT NULL DEFAULT 0,
    last_login_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS file_scans (
    id                  TEXT PRIMARY KEY,
    filename            TEXT NOT NULL,
    file_size           INTEGER NOT NULL,
    md5                 TEXT NOT NULL,
    sha256              TEXT NOT NULL,
    entropy             INTEGER NOT NULL,
    file_type           TEXT NOT NULL,
    suspicious_strings  TEXT,
    pe_characteristics  TEXT,
    risk_score          INTEGER NOT NULL,
    classification      TEXT NOT NULL,
    analyzed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    source      TEXT NOT NULL,
    severity    TEXT NOT NULL,
    score       INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'NEW',
    description TEXT NOT NULL,
    evidence    TEXT,
    incident_id TEXT,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incidents (
    id                      TEXT PRIMARY KEY,
    title                   TEXT NOT NULL,
    severity                TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'OPEN',
    correlated_events_count INTEGER NOT NULL DEFAULT 1,
    summary                 TEXT NOT NULL,
    timeline                TEXT NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Workspace and user configuration settings
CREATE TABLE IF NOT EXISTS settings (
    id                  TEXT PRIMARY KEY DEFAULT 'default',
    name                TEXT NOT NULL DEFAULT 'Avery Mitchell',
    workspace_name      TEXT NOT NULL DEFAULT 'Northstar Studio',
    notification_email  TEXT NOT NULL DEFAULT 'avery@northstar.studio',
    critical_alerts     BOOLEAN NOT NULL DEFAULT TRUE,
    weekly_digest       BOOLEAN NOT NULL DEFAULT FALSE,
    data_retention      TEXT NOT NULL DEFAULT '30 days',
    scan_confirmation   BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(type);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_network_events_attack_class ON network_events(attack_class);
CREATE INDEX IF NOT EXISTS idx_network_events_timestamp ON network_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
