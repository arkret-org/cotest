// Mock delivery capture for ordinary account registration and recovery email.

import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { InspectLog, handleInspect } from "./_shared/inspect.mjs";
import { readJson } from "./_shared/http.mjs";

const port = parseInt(process.env.MOCK_EMAIL_PORT ?? "0", 10);
const defaultTtlSeconds = parseInt(process.env.MOCK_EMAIL_TOKEN_TTL_SECONDS ?? "900", 10);


// to -> [{ message_id, token, subject, body, body_html, received_at, expires_at }]
const inbox = new Map();
const sendLog = new InspectLog("sent");
const failedRecipients = new Set();



function normalizeRecipient(raw) {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== "string") return null;
  const match = value.match(/<([^<>@\s]+@[^<>@\s]+)>/);
  return (match?.[1] ?? value).trim();
}

function extractTokenCandidate(body) {
  if (typeof body.token === "string" && body.token.trim()) return body.token.trim();
  for (const key of ["token", "verification_token", "code", "verification_code"]) {
    const value = body.tags?.[key] ?? body.headers?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }

  const haystack = [body.body, body.body_html, body.text_body, body.html_body, body.subject]
    .filter((value) => typeof value === "string")
    .join("\n");
  const invite = haystack.match(/invite:\/\/([A-Za-z0-9._~:-]+)/);
  if (invite) return invite[1];
  const urlToken = haystack.match(/[?&](?:token|code)=([A-Za-z0-9._~:-]+)/);
  if (urlToken) return urlToken[1];
  const shortCode = haystack.match(/\b[0-9]{6,12}\b/);
  if (shortCode) return shortCode[0];

  return `mock-${randomUUID()}`;
}

function normalizeSendPayload(body) {
  const to = normalizeRecipient(body.to ?? body.recipient);
  const token = extractTokenCandidate(body);
  return {
    to,
    token,
    subject: body.subject ?? "Arkret invite",
    body: body.body ?? body.text_body ?? `You've been invited. Open: invite://${token}`,
    body_html:
      body.body_html ??
      body.html_body ??
      `<p>You've been invited.</p><p><a href="invite://${token}">Accept invite</a></p>`,
    ttl_seconds: body.ttl_seconds,
    source_payload: body,
  };
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("content-type", "application/json");

  const issuer = `http://127.0.0.1:${server.address()?.port ?? port}`;

  if (url.pathname === "/inspect") {
    if (req.method === "POST") {
      const body = await readJson(req);
      const fault = body?.delivery_failure;
      const valid = body && Object.keys(body).length === 1 && fault
        && Object.keys(fault).length === 2
        && typeof fault.to === "string" && fault.to === fault.to.trim()
        && /^[^<>@\s]+@[^<>@\s]+$/.test(fault.to) && fault.to.length <= 320
        && typeof fault.enabled === "boolean";
      if (!valid) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: "invalid_delivery_failure_control" }));
        return;
      }
      if (fault.enabled) failedRecipients.add(fault.to);
      else failedRecipients.delete(fault.to);
      // No private recipient, attempted message or code appears in controls.
      res.end(JSON.stringify({ configured: true, enabled: fault.enabled }));
      return;
    }
    if (req.method === "DELETE") failedRecipients.clear();
    const handled = handleInspect(req, res, {
      service: "mock-email",
      logs: [sendLog],
      extra: {
        inbox_count: inbox.size,
      },
    });
    if (handled) return;
  }



  if (url.pathname === "/mock/email/verification/send" && req.method === "POST") {
    const body = await readJson(req);
    if (!body) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_json" }));
      return;
    }
    const payload = normalizeSendPayload(body);
    if (!payload.to || !payload.token) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_to_or_token" }));
      return;
    }
    const ttl = Number.isFinite(payload.ttl_seconds) ? payload.ttl_seconds : defaultTtlSeconds;
    const expiresAtMs = Date.now() + ttl * 1000;
    const message_id = `msg-${randomUUID()}`;
    const failed = failedRecipients.has(payload.to);
    const message = {
      message_id,
      token: payload.token,
      subject: payload.subject,
      body: payload.body,
      body_html: payload.body_html,
      received_at: new Date().toISOString(),
      expires_at: new Date(expiresAtMs).toISOString(),
      delivery_status: failed ? "failed" : "delivered",
    };
    const list = inbox.get(payload.to) ?? [];
    list.push(message);
    inbox.set(payload.to, list);
    if (failed) {
      // The transport actually fails; only the private in-memory inbox keeps
      // attempted bodies so tests can distinguish attempts from delivery.
      res.statusCode = 503;
      res.end(JSON.stringify({ error: "mock_delivery_unavailable" }));
      return;
    }
    sendLog.record({
      to: payload.to,
      token: payload.token,
      message_id,
      expires_at: message.expires_at,
      source_payload: payload.source_payload,
    });
    res.statusCode = 200;
    res.end(JSON.stringify({ message_id, expires_at: message.expires_at }));
    return;
  }

  if (url.pathname === "/mock/email/verification/inbox" && req.method === "GET") {
    const to = url.searchParams.get("to");
    if (!to) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_to" }));
      return;
    }
    res.end(JSON.stringify({ messages: inbox.get(to) ?? [] }));
    return;
  }



  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(`[mock-email] listening on http://127.0.0.1:${actual.port}`);
});
