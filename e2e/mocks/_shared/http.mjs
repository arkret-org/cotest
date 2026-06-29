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
/// code unit, no whitespace, `undefined` members dropped). This is the single
/// canonical-JSON implementation for the `.mjs` runtime (mocks + scripts), kept
/// in lock-step with the TypeScript helper `canonicalJson` in
/// `e2e/helpers/soland-api.ts` so mock/script-computed digests cannot drift
/// from the harness. Numbers are validated to be finite integers (the only
/// number form the conformance encoding profile permits) so a boundary value
/// fails loudly here instead of silently diverging from the TS authority.
export function canonicalJson(value) {
  if (value === null) {
    return "null";
  }
  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value) || !Number.isInteger(value)) {
        throw new TypeError(`non-canonical JSON number: ${value}`);
      }
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw new TypeError(`non-canonical JSON value: ${typeof value}`);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  return `{${Object.keys(value)
    .filter((key) => value[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}
