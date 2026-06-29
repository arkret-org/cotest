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

/// Deterministic canonical JSON (JCS-style: sorted keys, `undefined` members
/// dropped). Mirrors the helper-side `canonicalJson` so mock-computed digests
/// match the harness.
export function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
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
