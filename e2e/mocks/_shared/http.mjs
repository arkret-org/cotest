// Shared HTTP request/response helpers for cotest mock servers.
//
// Every mock previously re-defined a byte-identical `readJson(req)` (and a
// couple re-defined `canonicalJson`). They are consolidated here so the body
// parsing / canonical-JSON encoding cannot drift between mocks.

/// Read and JSON-parse a request body. Returns `{}` for an empty body and
/// `null` when the body is present but not valid JSON (so callers can answer
/// `invalid_json`).
export async function readJson(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString());
  } catch {
    return null;
  }
}

/// Write a JSON response with the given status code.
export function sendJson(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

/// Deterministic canonical JSON (RFC 8785 / JCS-style: keys sorted by UTF-16
/// code unit, no whitespace). This is the single canonical-JSON implementation
/// for the `.mjs` runtime (mocks + scripts), kept in lock-step with the
/// TypeScript authority `canonicalJson` in `e2e/helpers/soland-api.ts` (itself
/// a port of cokret-rust-sdk/crates/core/src/canonical.rs) so mock/script
/// computed digests cannot drift from the harness. The full canonical-profile
/// validation matches the TS port: safe-integer-only numbers, `-0` rejected,
/// BOM / non-NFC strings rejected, `undefined` object members rejected, and
/// non-plain object prototypes rejected. Drift is guarded by the third lane of
/// e2e/tests/conformance/canonical-cross-lang.spec.ts over the shared
/// e2e/fixtures/canonical-cross-check.json golden.
export function canonicalJson(value) {
  return canonicalJsonValue(value, "$");
}

function canonicalJsonValue(value, path) {
  if (value === null) {
    return "null";
  }
  switch (typeof value) {
    case "string":
      assertCanonicalString(value, path);
      return JSON.stringify(value);
    case "number":
      assertCanonicalNumber(value, path);
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "object":
      break;
    default:
      throw new TypeError(`non-canonical JSON value at ${path}: ${typeof value}`);
  }

  if (Array.isArray(value)) {
    return `[${value
      .map((item, index) => canonicalJsonValue(item, `${path}[${index}]`))
      .join(",")}]`;
  }

  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError(`non-canonical JSON object at ${path}`);
  }

  return `{${Object.keys(value)
    .sort(compareJsonKeys)
    .map((key) => {
      assertCanonicalString(key, `${path}.${key}`);
      if (value[key] === undefined) {
        throw new TypeError(`non-canonical undefined member at ${path}.${key}`);
      }
      return `${JSON.stringify(key)}:${canonicalJsonValue(value[key], `${path}.${key}`)}`;
    })
    .join(",")}}`;
}

function compareJsonKeys(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function assertCanonicalString(value, path) {
  if (value.includes("\uFEFF")) {
    throw new TypeError(`non-canonical BOM in string at ${path}`);
  }
  if (value.normalize("NFC") !== value) {
    throw new TypeError(`non-canonical non-NFC string at ${path}`);
  }
}

function assertCanonicalNumber(value, path) {
  if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
    throw new TypeError(`non-canonical number at ${path}: ${value}`);
  }
}

/// Canonical RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`, seconds only).
/// soland validates every string `*_at` field inside event content blocks with
/// cokret-sdk `validate_timestamp_canonical`, which rejects fractional
/// seconds — never emit a raw `toISOString()` from a mock. Mirrors
/// `canonicalTimestamp` in e2e/helpers/soland-api.ts.
export function canonicalTimestamp(date = new Date()) {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}
