// Mock Push Gateway — a desensitized push notification gateway shim that
// abstracts APNs / FCM / generic HTTP push, exposed for cotest joint-e2e to
// verify push delivery, Do-Not-Disturb (DnD) suppression, and blind wakeup
// (E2EE-friendly desensitized payloads).
//
// Implements the wire contract described by
// `cokret-spec/spec/v1/zh/discovery/push-notifications.md`:
//   - blind wakeup as the default interop privacy baseline
//   - per-pusher registration with optional DnD windows
//   - signed delivery receipts (Ed25519 JWT-shaped) so senders can prove the
//     gateway accepted a payload without re-revealing E2EE content.
//
// Endpoints:
//   POST /_cokret/edge/push/register
//     body = { pusher_id, app_id, push_key, push_token, device_did, kind, dnd? }
//     Register a pusher. `kind` ∈ {"http","apns","fcm"}.
//   POST /_cokret/edge/push/notify
//     body = { pusher_id, payload, blind_wake?, priority?, event_id? }
//     Honours DnD: if the gateway's current time falls inside either the
//     pusher's DnD window or the global quiet_hours window, the call logs
//     "suppressed" and does NOT deliver. Otherwise the payload is recorded
//     in the per-pusher inbox and a signed delivery receipt is returned.
//     `blind_wake=true` requires the payload to look desensitized (no
//     plaintext-shaped identifiers — enforced as a best-effort lint).
//   GET  /_cokret/edge/push/inbox?pusher_id=<id>
//     List delivered payloads for that pusher.
//   POST /scenarios
//     body = { quiet_hours?: {start, end, tz}, force_failure?: bool }
//     Configure global mock behaviour for the next requests.
//   DELETE /scenarios
//     Clear scenario config (force_failure off, quiet_hours cleared).
//   DELETE /inspect
//     Reset all inspect logs.
//   GET  /jwks
//     Public key used to verify delivery receipts.
//   GET  /inspect
//     handleInspect middleware dump (logs: delivered, suppressed, registered).
//
// In-memory only; state resets per harness run.

import { createServer } from "node:http";
import { createHash, randomUUID, sign as cryptoSign } from "node:crypto";
import { createEd25519KeyPair, b64url } from "./_shared/keypairs.mjs";
import { InspectLog, handleInspect } from "./_shared/inspect.mjs";

const port = parseInt(process.env.MOCK_PUSH_GATEWAY_PORT ?? "0", 10);
const issuer =
  process.env.MOCK_PUSH_GATEWAY_ISS ??
  `did:web:push-gateway.joint-e2e.local#${randomUUID().slice(0, 8)}`;

const { privateKey, publicKey, jwks } = createEd25519KeyPair(
  "mock-push-gateway-key-1",
);
const publicJwk = publicKey.export({ format: "jwk" });

// pusher_id -> { app_id, push_key, push_token, device_did, kind, dnd? }
const pushers = new Map();
// pusher_id -> [delivered payload, ...]
const inbox = new Map();

const registeredLog = new InspectLog("registered");
const deliveredLog = new InspectLog("delivered");
const suppressedLog = new InspectLog("suppressed");

// Scenario knobs settable via POST /scenarios.
const scenarios = {
  quietHours: null, // { start: "HH:MM", end: "HH:MM", tz: "Asia/Shanghai" }
  forceFailure: false,
};

function parseHHMM(s) {
  if (typeof s !== "string") return null;
  const m = /^(\d{1,2}):(\d{2})$/.exec(s);
  if (!m) return null;
  const h = parseInt(m[1], 10);
  const min = parseInt(m[2], 10);
  if (h < 0 || h > 23 || min < 0 || min > 59) return null;
  return h * 60 + min;
}

// Compute the local "minutes since 00:00" for the given timezone using
// Intl.DateTimeFormat. Falls back to UTC if the tz is unknown.
function localMinutes(tz) {
  const now = new Date();
  try {
    const fmt = new Intl.DateTimeFormat("en-US", {
      timeZone: tz ?? "UTC",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
    const parts = fmt.formatToParts(now);
    const h = parseInt(parts.find((p) => p.type === "hour")?.value ?? "0", 10);
    const m = parseInt(parts.find((p) => p.type === "minute")?.value ?? "0", 10);
    // Intl can emit "24" for midnight in some hour12:false locales; normalize.
    return ((h % 24) * 60 + m) % (24 * 60);
  } catch {
    return now.getUTCHours() * 60 + now.getUTCMinutes();
  }
}

// Returns true if `nowMin` is inside [startMin, endMin), supporting wrap-around
// windows like 22:00 -> 08:00.
function inWindow(nowMin, startMin, endMin) {
  if (startMin === endMin) return false;
  if (startMin < endMin) {
    return nowMin >= startMin && nowMin < endMin;
  }
  // Wrap across midnight.
  return nowMin >= startMin || nowMin < endMin;
}

function dndActive(dnd) {
  if (!dnd) return false;
  const start = parseHHMM(dnd.start);
  const end = parseHHMM(dnd.end);
  if (start == null || end == null) return false;
  const now = localMinutes(dnd.tz ?? "UTC");
  return inWindow(now, start, end);
}

// Heuristic check: a blind-wake payload MUST NOT carry plaintext-shaped
// identifiers. We refuse keys that the spec explicitly bans.
const FORBIDDEN_BLIND_WAKE_KEYS = new Set([
  "body",
  "title",
  "message",
  "sender",
  "sender_did",
  "sender_display_name",
  "principal_id",
  "realm_id",
  "realm_name",
  "flow_id",
  "flow_name",
  "message_id",
  "event_id",
  "room_name",
  "reaction",
  "attachment_name",
]);

function violatesBlindWake(payload) {
  if (!payload || typeof payload !== "object") return null;
  for (const key of Object.keys(payload)) {
    if (FORBIDDEN_BLIND_WAKE_KEYS.has(key)) return key;
  }
  return null;
}

function sha256Hex(input) {
  return createHash("sha256").update(input).digest("hex");
}

function signDeliveryReceipt({ pusher_id, payload }) {
  const header = { alg: "EdDSA", typ: "JWT", kid: "mock-push-gateway-key-1" };
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: issuer,
    jti: `rcpt-${randomUUID()}`,
    pusher_id,
    payload_digest: `sha256:${sha256Hex(JSON.stringify(payload ?? {}))}`,
    delivered_at: now,
    expires_at: now + 600,
  };
  const enc = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const sig = cryptoSign(null, Buffer.from(enc), privateKey);
  return { jwt: `${enc}.${b64url(sig)}`, claims };
}

async function readJson(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString());
  } catch {
    return null;
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("content-type", "application/json");

  if (url.pathname === "/inspect") {
    const handled = handleInspect(req, res, {
      service: "mock-push-gateway",
      logs: [registeredLog, deliveredLog, suppressedLog],
      extra: {
        issuer,
        public_jwk: publicJwk,
        pusher_count: pushers.size,
        scenarios: {
          quiet_hours: scenarios.quietHours,
          force_failure: scenarios.forceFailure,
        },
      },
    });
    if (handled) return;
  }

  if (url.pathname === "/jwks") {
    res.end(JSON.stringify(jwks));
    return;
  }

  if (url.pathname === "/scenarios") {
    if (req.method === "POST") {
      const body = await readJson(req);
      if (!body) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: "invalid_json" }));
        return;
      }
      if (body.quiet_hours !== undefined) {
        if (body.quiet_hours === null) {
          scenarios.quietHours = null;
        } else if (
          typeof body.quiet_hours === "object" &&
          parseHHMM(body.quiet_hours.start) != null &&
          parseHHMM(body.quiet_hours.end) != null
        ) {
          scenarios.quietHours = {
            start: body.quiet_hours.start,
            end: body.quiet_hours.end,
            tz: body.quiet_hours.tz ?? "UTC",
          };
        } else {
          res.statusCode = 400;
          res.end(JSON.stringify({ error: "invalid_quiet_hours" }));
          return;
        }
      }
      if (body.force_failure !== undefined) {
        scenarios.forceFailure = Boolean(body.force_failure);
      }
      res.end(
        JSON.stringify({
          ok: true,
          quiet_hours: scenarios.quietHours,
          force_failure: scenarios.forceFailure,
        }),
      );
      return;
    }
    if (req.method === "DELETE") {
      scenarios.quietHours = null;
      scenarios.forceFailure = false;
      res.end(JSON.stringify({ ok: true }));
      return;
    }
  }

  if (url.pathname === "/_cokret/edge/push/register" && req.method === "POST") {
    const body = await readJson(req);
    if (
      !body ||
      !body.pusher_id ||
      !body.app_id ||
      !body.push_key ||
      !body.push_token ||
      !body.device_did ||
      !body.kind
    ) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_required_field" }));
      return;
    }
    if (!["http", "apns", "fcm"].includes(body.kind)) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "invalid_kind" }));
      return;
    }
    const entry = {
      app_id: body.app_id,
      push_key: body.push_key,
      push_token: body.push_token,
      device_did: body.device_did,
      kind: body.kind,
      dnd: body.dnd ?? null,
      registered_at: new Date().toISOString(),
    };
    pushers.set(body.pusher_id, entry);
    if (!inbox.has(body.pusher_id)) inbox.set(body.pusher_id, []);
    registeredLog.record({
      pusher_id: body.pusher_id,
      app_id: entry.app_id,
      device_did: entry.device_did,
      kind: entry.kind,
      dnd: entry.dnd,
    });
    res.end(
      JSON.stringify({
        ok: true,
        pusher_id: body.pusher_id,
        registered_at: entry.registered_at,
      }),
    );
    return;
  }

  if (url.pathname === "/_cokret/edge/push/notify" && req.method === "POST") {
    const body = await readJson(req);
    if (!body || !body.pusher_id || body.payload === undefined) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_pusher_id_or_payload" }));
      return;
    }
    const pusher = pushers.get(body.pusher_id);
    if (!pusher) {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: "pusher_unknown" }));
      return;
    }
    if (scenarios.forceFailure) {
      suppressedLog.record({
        pusher_id: body.pusher_id,
        reason: "force_failure",
        event_id: body.event_id ?? null,
      });
      res.statusCode = 502;
      res.end(JSON.stringify({ error: "force_failure", rejected: [pusher.push_key] }));
      return;
    }
    if (body.blind_wake === true) {
      const offender = violatesBlindWake(body.payload);
      if (offender) {
        res.statusCode = 422;
        res.end(
          JSON.stringify({
            error: "blind_wake_violation",
            forbidden_key: offender,
          }),
        );
        return;
      }
    }
    // DnD: per-pusher window wins; global quiet_hours fallback.
    let suppressedReason = null;
    if (dndActive(pusher.dnd)) {
      suppressedReason = "pusher_dnd";
    } else if (dndActive(scenarios.quietHours)) {
      suppressedReason = "global_quiet_hours";
    }
    if (suppressedReason) {
      suppressedLog.record({
        pusher_id: body.pusher_id,
        reason: suppressedReason,
        event_id: body.event_id ?? null,
        priority: body.priority ?? "normal",
        blind_wake: Boolean(body.blind_wake),
      });
      res.statusCode = 200;
      res.end(
        JSON.stringify({
          ok: true,
          delivered: false,
          suppressed: true,
          reason: suppressedReason,
        }),
      );
      return;
    }
    const { jwt: receipt, claims } = signDeliveryReceipt({
      pusher_id: body.pusher_id,
      payload: body.payload,
    });
    const delivered = {
      pusher_id: body.pusher_id,
      app_id: pusher.app_id,
      device_did: pusher.device_did,
      kind: pusher.kind,
      blind_wake: Boolean(body.blind_wake),
      priority: body.priority ?? "normal",
      event_id: body.event_id ?? null,
      payload: body.payload,
      delivery_receipt: receipt,
      delivered_at: new Date(claims.delivered_at * 1000).toISOString(),
    };
    inbox.get(body.pusher_id).push(delivered);
    deliveredLog.record({
      pusher_id: body.pusher_id,
      event_id: delivered.event_id,
      blind_wake: delivered.blind_wake,
      priority: delivered.priority,
      payload_digest: claims.payload_digest,
    });
    res.end(
      JSON.stringify({
        ok: true,
        delivered: true,
        delivery_receipt: receipt,
        delivered_at: delivered.delivered_at,
        rejected: [],
      }),
    );
    return;
  }

  if (url.pathname === "/_cokret/edge/push/inbox" && req.method === "GET") {
    const pusher_id = url.searchParams.get("pusher_id");
    if (!pusher_id) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "missing_pusher_id" }));
      return;
    }
    res.end(JSON.stringify({ pusher_id, pushes: inbox.get(pusher_id) ?? [] }));
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address();
  console.error(
    `[mock-push-gateway] listening on http://127.0.0.1:${actual.port} (iss=${issuer})`,
  );
});
