// Transport-only regression against the real run-scoped Caddy. No business
// acceptance or verified DID credit is assigned to the small static fixtures.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import https from 'node:https';

const [port, caPath] = process.argv.slice(2);
const ca = readFileSync(caPath);
const origins = ['http://127.0.0.1:41001', 'http://127.0.0.1:41002'];
const paths = [
  '/_arkret/find/directory/describe',
  '/_arkret/find/directory/search-realms',
  '/_arkret/find/directory/resolve-realm',
  '/webvh/flagon/did.json',
  '/webvh/flagon/did.jsonl',
  '/webvh/flagon/did-witness.json',
];
const observations = [];
function request(path, { origin, method = 'GET', preflight = false } = {}) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (origin) headers.Origin = origin;
    if (preflight) {
      headers['Access-Control-Request-Method'] = path.includes('search') ? 'POST' : 'GET';
      headers['Access-Control-Request-Headers'] = 'Arkret-Operation, Content-Type';
    }
    const req = https.request({ hostname: 'localhost', family: 4, port: Number(port), path, method, headers, ca }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        const result = { path, origin, method, status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') };
        observations.push(result); resolve(result);
      });
      res.on('error', reject);
    });
    req.setTimeout(5000, () => req.destroy(new Error('Caddy regression request timed out')));
    req.on('error', reject); req.end();
  });
}
for (const origin of origins) {
  for (const path of paths) {
    const result = await request(path, { origin });
    assert.equal(result.status, path.endsWith('did-witness.json') ? 404 : 200);
    assert.equal(result.headers['access-control-allow-origin'], origin);
    assert.match(result.headers.vary, /(?:^|,\s*)Origin(?:,|$)/);
    assert.equal(result.headers['access-control-allow-credentials'], undefined);
    assert.equal(result.headers['access-control-allow-methods'], 'GET, POST, OPTIONS');
    assert.equal(result.headers['access-control-allow-headers'], 'Arkret-Operation, Content-Type');
  }
  for (const path of paths.slice(0, 3)) {
    const result = await request(path, { origin, method: 'OPTIONS', preflight: true });
    assert.equal(result.status, 204);
    assert.equal(result.headers['access-control-allow-origin'], origin);
  }
}
for (const origin of [undefined, 'null', 'https://evil.example', origins[0] + '.evil.example', 'http://127.0.0.1:41003']) {
  for (const path of paths) {
    const result = await request(path, { origin });
    assert.equal(result.headers['access-control-allow-origin'], undefined);
    assert.equal(result.headers['access-control-allow-credentials'], undefined);
  }
  const preflight = await request(paths[1], { origin, method: 'OPTIONS', preflight: true });
  assert.equal(preflight.headers['access-control-allow-origin'], undefined);
}
for (const path of ['/_flagon/admin/audit', '/health', '/webvh/flagon/private.key', '/webvh/flagon/did.json/extra', '/_arkret/find/directory/unknown', '/_arkret/describe']) {
  assert.equal((await request(path, { origin: origins[0] })).headers['access-control-allow-origin'], undefined);
}
assert.equal((await request(paths[0], { origin: origins[0], method: 'DELETE' })).headers['access-control-allow-origin'], undefined);
assert.equal((await request('/webvh/flagon/did.json', { origin: origins[0] })).body, '{"public":"fixture"}\n');
// Capture the real static MIME header so the SDK's accepted content types can
// be checked without assigning cryptographic validity to these fixture bytes.
const log = await request('/webvh/flagon/did.jsonl', { origin: origins[0] });
assert.match(log.headers['content-type'], /^application\/(?:json|jsonl|x-ndjson|did\+json)(?:;|$)/);
process.stdout.write(JSON.stringify({ passed: true, requests: observations.length, observations }, null, 2) + '\n');
