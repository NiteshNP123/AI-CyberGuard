import { pgTable, text, timestamp, integer, boolean } from "drizzle-orm/pg-core";

export const securityEventsTable = pgTable("security_events", {
  id: text("id").primaryKey(),
  type: text("type").notNull(), // URL_ANALYSIS, MESSAGE_ANALYSIS, NETWORK_IDS, DNS_ANOMALY, LOGIN_ANOMALY, FILE_ANALYSIS, WIFI_SECURITY, SECRET_LEAK, QR_ANALYSIS
  title: text("title").notNull(),
  detail: text("detail").notNull(),
  severity: text("severity").notNull(), // LOW, MEDIUM, HIGH, CRITICAL
  score: integer("score").notNull(), // 0 - 100
  source: text("source").notNull(),
  metadata: text("metadata"), // JSON-encoded string
  timestamp: timestamp("timestamp", { withTimezone: true }).defaultNow().notNull(),
});

export type SecurityEventRecord = typeof securityEventsTable.$inferSelect;
export type InsertSecurityEvent = typeof securityEventsTable.$inferInsert;

export const urlScansTable = pgTable("url_scans", {
  id: text("id").primaryKey(),
  url: text("url").notNull(),
  domain: text("domain").notNull(),
  classification: text("classification").notNull(), // SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN
  riskScore: integer("risk_score").notNull(),
  confidence: integer("confidence").notNull(),
  summary: text("summary").notNull(),
  indicators: text("indicators").notNull(), // JSON string array
  signals: text("signals").notNull(), // JSON string array of {name, detail, weight}
  mlFeatures: text("ml_features"), // JSON object of extracted features & SHAP attribution
  recommendation: text("recommendation").notNull(),
  analyzedAt: timestamp("analyzed_at", { withTimezone: true }).defaultNow().notNull(),
});

export type UrlScanRecord = typeof urlScansTable.$inferSelect;
export type InsertUrlScan = typeof urlScansTable.$inferInsert;

export const messageScansTable = pgTable("message_scans", {
  id: text("id").primaryKey(),
  message: text("message").notNull(),
  classification: text("classification").notNull(), // SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN
  riskScore: integer("risk_score").notNull(),
  confidence: integer("confidence").notNull(),
  summary: text("summary").notNull(),
  indicators: text("indicators").notNull(), // JSON string array
  signals: text("signals").notNull(), // JSON string array of {name, detail, weight}
  tokenAttributions: text("token_attributions"), // JSON string array of {token, score, category}
  recommendation: text("recommendation").notNull(),
  analyzedAt: timestamp("analyzed_at", { withTimezone: true }).defaultNow().notNull(),
});

export type MessageScanRecord = typeof messageScansTable.$inferSelect;
export type InsertMessageScan = typeof messageScansTable.$inferInsert;

export const networkEventsTable = pgTable("network_events", {
  id: text("id").primaryKey(),
  srcIp: text("src_ip").notNull(),
  dstIp: text("dst_ip").notNull(),
  srcPort: integer("src_port").notNull(),
  dstPort: integer("dst_port").notNull(),
  protocol: text("protocol").notNull(),
  flowDuration: integer("flow_duration").notNull(),
  packetCount: integer("packet_count").notNull(),
  byteCount: integer("byte_count").notNull(),
  attackClass: text("attack_class").notNull(), // NORMAL, PORT_SCAN, DOS_DDOS, BRUTE_FORCE, BOTNET_ANOMALY, WEB_ATTACK
  severity: text("severity").notNull(), // LOW, MEDIUM, HIGH, CRITICAL
  riskScore: integer("risk_score").notNull(),
  confidence: integer("confidence").notNull(),
  flowFeatures: text("flow_features"), // JSON string
  rawTelemetry: text("raw_telemetry"),
  timestamp: timestamp("timestamp", { withTimezone: true }).defaultNow().notNull(),
});

export type NetworkEventRecord = typeof networkEventsTable.$inferSelect;
export type InsertNetworkEvent = typeof networkEventsTable.$inferInsert;

export const dnsEventsTable = pgTable("dns_events", {
  id: text("id").primaryKey(),
  queryDomain: text("query_domain").notNull(),
  queryType: text("query_type").notNull(),
  entropy: integer("entropy").notNull(),
  isDga: boolean("is_dga").notNull().default(false),
  isTunneling: boolean("is_tunneling").notNull().default(false),
  severity: text("severity").notNull(),
  riskScore: integer("risk_score").notNull(),
  timestamp: timestamp("timestamp", { withTimezone: true }).defaultNow().notNull(),
});

export type DnsEventRecord = typeof dnsEventsTable.$inferSelect;
export type InsertDnsEvent = typeof dnsEventsTable.$inferInsert;

export const loginEventsTable = pgTable("login_events", {
  id: text("id").primaryKey(),
  userId: text("user_id"),
  username: text("username").notNull(),
  ipAddress: text("ip_address").notNull(),
  userAgent: text("user_agent").notNull(),
  status: text("status").notNull(), // SUCCESS, FAILED
  isAnomaly: boolean("is_anomaly").notNull().default(false),
  anomalyReason: text("anomaly_reason"),
  riskScore: integer("risk_score").notNull(),
  timestamp: timestamp("timestamp", { withTimezone: true }).defaultNow().notNull(),
});

export type LoginEventRecord = typeof loginEventsTable.$inferSelect;
export type InsertLoginEvent = typeof loginEventsTable.$inferInsert;

export const fileScansTable = pgTable("file_scans", {
  id: text("id").primaryKey(),
  filename: text("filename").notNull(),
  fileSize: integer("file_size").notNull(),
  md5: text("md5").notNull(),
  sha256: text("sha256").notNull(),
  entropy: integer("entropy").notNull(),
  fileType: text("file_type").notNull(),
  suspiciousStrings: text("suspicious_strings"),
  peCharacteristics: text("pe_characteristics"),
  riskScore: integer("risk_score").notNull(),
  classification: text("classification").notNull(),
  analyzedAt: timestamp("analyzed_at", { withTimezone: true }).defaultNow().notNull(),
});

export type FileScanRecord = typeof fileScansTable.$inferSelect;
export type InsertFileScan = typeof fileScansTable.$inferInsert;

export const alertsTable = pgTable("alerts", {
  id: text("id").primaryKey(),
  title: text("title").notNull(),
  source: text("source").notNull(),
  severity: text("severity").notNull(), // LOW, MEDIUM, HIGH, CRITICAL
  score: integer("score").notNull(),
  status: text("status").notNull().default("NEW"), // NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE
  description: text("description").notNull(),
  evidence: text("evidence"), // JSON string
  incidentId: text("incident_id"),
  timestamp: timestamp("timestamp", { withTimezone: true }).defaultNow().notNull(),
});

export type AlertRecord = typeof alertsTable.$inferSelect;
export type InsertAlert = typeof alertsTable.$inferInsert;

export const incidentsTable = pgTable("incidents", {
  id: text("id").primaryKey(),
  title: text("title").notNull(),
  severity: text("severity").notNull(), // LOW, MEDIUM, HIGH, CRITICAL
  status: text("status").notNull().default("OPEN"), // OPEN, INVESTIGATING, CONTAINED, RESOLVED
  correlatedEventsCount: integer("correlated_events_count").notNull().default(1),
  summary: text("summary").notNull(),
  timeline: text("timeline").notNull(), // JSON array
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

export type IncidentRecord = typeof incidentsTable.$inferSelect;
export type InsertIncident = typeof incidentsTable.$inferInsert;

// Persistent per-user behavioral login baseline (survives restarts)
export const loginProfilesTable = pgTable("login_profiles", {
  username: text("username").primaryKey(),
  knownIps: text("known_ips").notNull().default("[]"),       // JSON array of known IP strings
  knownUserAgents: text("known_user_agents").notNull().default("[]"), // JSON array of known UA strings
  failedAttempts: integer("failed_attempts").notNull().default(0),
  lastLoginAt: timestamp("last_login_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

export type LoginProfileRecord = typeof loginProfilesTable.$inferSelect;
export type InsertLoginProfile = typeof loginProfilesTable.$inferInsert;

