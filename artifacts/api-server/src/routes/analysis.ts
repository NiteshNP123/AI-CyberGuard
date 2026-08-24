import { randomUUID } from "node:crypto";
import { Router, type IRouter } from "express";
import { AnalyzeMessageBody, AnalyzeMessageResponse, AnalyzeUrlBody, AnalyzeUrlResponse } from "@workspace/api-zod";

const router: IRouter = Router();
const now = () => new Date().toISOString();

router.post("/analysis/url", (req, res) => {
  const parsed = AnalyzeUrlBody.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Enter a valid URL to analyze." });
  let url: URL;
  try { url = new URL(parsed.data.url.includes("://") ? parsed.data.url : `https://${parsed.data.url}`); }
  catch { return res.status(400).json({ error: "That URL could not be parsed safely." }); }

  const hostname = url.hostname.toLowerCase();
  const indicators: string[] = [];
  const signals: { name: string; detail: string; weight: number }[] = [];
  if (url.protocol !== "https:") { indicators.push("No HTTPS transport"); signals.push({ name: "Transport security", detail: "The URL does not use encrypted HTTPS transport.", weight: 24 }); }
  if (hostname.includes("xn--")) { indicators.push("Punycode domain"); signals.push({ name: "Domain encoding", detail: "Punycode can obscure lookalike characters in a domain name.", weight: 34 }); }
  if (hostname.split(".").length > 3) { indicators.push("Deep subdomain chain"); signals.push({ name: "Domain structure", detail: "Multiple subdomain levels increase impersonation risk.", weight: 16 }); }
  if (/[0-9]{4,}/.test(hostname)) { indicators.push("Numeric domain pattern"); signals.push({ name: "Domain reputation signal", detail: "A numeric-heavy hostname is less typical for an established brand.", weight: 14 }); }
  if (url.username || url.password) { indicators.push("Embedded credentials"); signals.push({ name: "URL obfuscation", detail: "Credentials embedded in a URL can hide the true destination.", weight: 30 }); }
  const riskScore = Math.min(100, 8 + signals.reduce((sum, signal) => sum + signal.weight, 0));
  const classification = riskScore >= 61 ? "SUSPICIOUS" : "SAFE";
  const data = { id: randomUUID(), classification, riskScore, confidence: signals.length ? 91 : 86, summary: signals.length ? "This URL contains structural signals that warrant verification before you continue." : "No significant structural risk indicators were found in this URL.", indicators, signals, recommendation: signals.length ? "Verify the domain through a trusted bookmark and avoid entering credentials until confirmed." : "Continue only if you recognize the domain and expected this link.", analyzedAt: now() };
  return res.json(AnalyzeUrlResponse.parse(data));
});

router.post("/analysis/message", (req, res) => {
  const parsed = AnalyzeMessageBody.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Paste at least 10 characters of message text." });
  const text = parsed.data.message;
  const lower = text.toLowerCase();
  const rules = [
    ["Urgency language", /urgent|immediately|within \d+ hours|act now|suspend/i, 25, "The message pressures the recipient to act before verifying the request."],
    ["Credential request", /password|login|verify your account|one[- ]time code|otp|credentials/i, 28, "Requests for credentials or verification codes are common phishing tactics."],
    ["Financial incentive", /refund|invoice|payment|prize|gift card|wire transfer|crypto/i, 21, "Financial themes can be used to make an untrusted request feel legitimate."],
    ["Impersonation cue", /ceo|administrator|support team|security team|helpdesk/i, 18, "The sender may be invoking authority or a trusted team to influence behavior."],
  ] as const;
  const signals = rules.filter(([, pattern]) => pattern.test(text)).map(([name, , weight, detail]) => ({ name, detail, weight }));
  const indicators = signals.map((signal) => signal.name);
  const riskScore = Math.min(100, 5 + signals.reduce((sum, signal) => sum + signal.weight, 0) + (lower.includes("http") ? 12 : 0));
  const classification = riskScore >= 61 ? "MALICIOUS" : riskScore >= 31 ? "SUSPICIOUS" : "SAFE";
  const data = { id: randomUUID(), classification, riskScore, confidence: signals.length ? 94 : 79, summary: signals.length ? "This message shows social-engineering patterns that should be verified out of band." : "No common fraud patterns were detected in the provided text.", indicators, signals, recommendation: signals.length ? "Do not click links or share codes. Contact the sender through a known channel and report the message if unexpected." : "Still verify the sender and context before acting on any request.", analyzedAt: now() };
  return res.json(AnalyzeMessageResponse.parse(data));
});

export default router;