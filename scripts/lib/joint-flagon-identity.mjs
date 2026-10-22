// Harness helper. Every WebVH byte/hash is emitted or checked by
// the run-scoped SDK wire CLI. This file defines no protocol DTO or crypto.
import { generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import https from 'node:https';

function need(value, name) {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`missing ${name}`);
  return value;
}
export function wire(binary, command, value) {
  const result = spawnSync(binary, [command], {
    input: JSON.stringify(value), encoding: 'utf8', windowsHide: true,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${command} failed: ${result.error?.message ?? result.stderr}`);
  }
  return JSON.parse(result.stdout);
}
function canonical(binary, value) {
  return wire(binary, 'canonical-json', { value }).canonical;
}
export async function mint({ wireBin, repoRoot, baseUrl, directory }) {
  const base = new URL(baseUrl);
  if (base.protocol !== 'https:' || base.pathname !== '/' || base.search || base.hash || base.username || base.password) {
    throw new Error('owned Directory base must be a canonical HTTPS origin');
  }
  if (existsSync(directory)) throw new Error('identity directory already exists');
  // Reuse the exact current shared encoder; do not copy Base58/SCID logic.
  const { encodeEd25519PubkeyMultibase, ed25519PrivateKeySeedB64url } =
    await import(pathToFileURL(path.join(repoRoot, 'e2e/helpers/encoding.ts')).href);
  const key = () => {
    const pair = generateKeyPairSync('ed25519');
    const raw = Buffer.from(pair.publicKey.export({ format: 'jwk' }).x, 'base64url');
    return { pair, multibase: encodeEd25519PubkeyMultibase(raw) };
  };
  const root = key(), next = key(), assertion = key();
  const localId = 'flagon';
  const placeholder = wire(wireBin, 'webvh-placeholder-did', { base_url: baseUrl, local_id: localId }).did;
  const method = `${placeholder}#directory-key`;
  const built = wire(wireBin, 'webvh-genesis', {
    base_url: baseUrl, local_id: localId,
    root_seed_b64url: ed25519PrivateKeySeedB64url(root.pair.privateKey),
    next_root_public_key_multibase: next.multibase,
    document: {
      '@context': ['https://www.w3.org/ns/did/v1'], id: placeholder,
      verificationMethod: [{ id: method, type: 'Multikey', controller: placeholder, publicKeyMultibase: assertion.multibase }],
      authentication: [method], assertionMethod: [method], alsoKnownAs: [],
      service: [{ id: `${placeholder}#service`, type: 'ArkretService', serviceKind: 'directory_service', serviceEndpoint: baseUrl }],
    },
  });
  mkdirSync(path.join(directory, 'webvh', localId), { recursive: true });
  const logPath = path.join(directory, 'webvh', localId, 'did.jsonl');
  const documentPath = path.join(directory, 'webvh', localId, 'did.json');
  writeFileSync(logPath, `${JSON.stringify(built.entry)}\n`, 'utf8');
  writeFileSync(documentPath, `${JSON.stringify(built.didDocument)}\n`, 'utf8');
  // Mint-time verification is useful but does not replace HTTPS retrieval.
  const verified = wire(wireBin, 'webvh-verify-log', { did: built.did, log_path: logPath, profile: 'service' });
  if (!verified.verified || verified.entry_count !== 1 || verified.head_version_id !== built.versionId) {
    throw new Error('SDK-generated service history did not verify');
  }
  const manifest = { did: built.did, version_id: built.versionId, base_url: baseUrl, log_path: logPath, document_path: documentPath };
  writeFileSync(path.join(directory, 'minted.json'), JSON.stringify(manifest, null, 2), 'utf8');
  // None of root/next/assertion private seeds are retained or logged.
  return manifest;
}
export function verifyFetched({ wireBin, directory, logPath, documentPath }) {
  const minted = JSON.parse(readFileSync(path.join(directory, 'minted.json'), 'utf8'));
  const verified = wire(wireBin, 'webvh-verify-log', { did: minted.did, log_path: logPath, profile: 'service' });
  const entries = readFileSync(logPath, 'utf8').split(/\r?\n/).filter(line => line.trim()).map(line => JSON.parse(line));
  const original = JSON.parse(readFileSync(minted.log_path, 'utf8').trim());
  const document = JSON.parse(readFileSync(documentPath, 'utf8'));
  if (!verified.verified || verified.entry_count !== 1 || entries.length !== 1 || verified.head_version_id !== minted.version_id ||
      canonical(wireBin, entries[0]) !== canonical(wireBin, original) ||
      canonical(wireBin, document) !== canonical(wireBin, original.state)) {
    throw new Error('fetched Directory history/document differs from exact minted original');
  }
  const digest = wire(wireBin, 'sha256-canonical-json', { value: entries[0] }).digest;
  return { did: minted.did, method_history_head: digest, version_id: verified.head_version_id, expected_service_id: verified.did_core_id };
}
export function assertDescribe({ describe, commitment, expectedServiceId = '' }) {
  if (!commitment.expected_service_id?.startsWith('ak:did_core:') || describe.service_id !== commitment.expected_service_id || describe.service_kind !== 'directory_service' ||
      describe.service_resolution?.did !== commitment.did ||
      describe.service_resolution?.method_history_head !== commitment.method_history_head ||
      describe.service_resolution?.version_id !== commitment.version_id ||
      (expectedServiceId && describe.service_id !== expectedServiceId) ||
      !describe.supported_operation_bundles?.includes('ak.operation_bundle.directory_service.public_read.v1')) {
    throw new Error('Directory describe does not match independently verified identity/role');
  }
  return describe.service_id;
}
function fetchBytes(url, caPath) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password) throw new Error('DID material requires credential-free HTTPS');
    const request = https.get(parsed, { ca: caPath ? readFileSync(caPath) : undefined }, response => {
      if (response.statusCode !== 200) { response.resume(); reject(new Error(`DID material ${url}: HTTP ${response.statusCode}`)); return; }
      const chunks = []; let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > 16 * 1024 * 1024) request.destroy(new Error('DID material exceeds 16MiB')); else chunks.push(chunk); });
      response.on('end', () => resolve(Buffer.concat(chunks)));
      response.on('error', reject);
    });
    request.setTimeout(15000, () => request.destroy(new Error(`DID material timeout: ${url}`)));
    request.on('error', reject);
  });
}
export async function verifyRemote({ wireBin, directory, did, logUrl, baseUrl, caPath, evidenceDirectory, expectedHistoryHead, expectedVersionId }) {
  need(did, 'DID');
  if (existsSync(evidenceDirectory)) throw new Error('verification evidence directory already exists');
  mkdirSync(evidenceDirectory, { recursive: true });
  const logPath = path.join(evidenceDirectory, 'fetched.did.jsonl');
  const documentPath = path.join(evidenceDirectory, 'fetched.did.json');
  let commitment;
  if (did.startsWith('did:web:')) {
    if (directory) throw new Error('owned mint uses WebVH, not a no-history alias');
    // The active adapter is the only locator authority, including every
    // path/port/host validity rule. Do not copy its grammar into Node.
    const url = wire(wireBin, 'did-web-document-url', { did }).document_url;
    writeFileSync(documentPath, await fetchBytes(url, caPath));
    const document = JSON.parse(readFileSync(documentPath, 'utf8'));
    if (document.id !== did) throw new Error('current did:web document id mismatch');
    const digest = wire(wireBin, 'did-document-digest', document);
    if (!digest.startsWith('sha256:')) throw new Error('SDK did:web digest has unexpected format');
    commitment = { did, method_history_head: digest, version_id: `synthetic-jcs-sha256:${digest.slice('sha256:'.length)}`, expected_service_id: wire(wireBin, 'project-did-core-id', { did }).did_core_id };
  } else {
    if (!did.startsWith('did:webvh:')) throw new Error('Directory fixture requires registered WebVH or explicit no-history Web service identity');
    const log = new URL(logUrl);
    if (!log.pathname.endsWith('/did.jsonl')) throw new Error('method-native log must end with did.jsonl');
    const documentUrl = new URL(log); documentUrl.pathname = log.pathname.slice(0, -1);
    writeFileSync(logPath, await fetchBytes(log, caPath));
    writeFileSync(documentPath, await fetchBytes(documentUrl, caPath));
    if (directory) {
    const minted = JSON.parse(readFileSync(path.join(directory, 'minted.json'), 'utf8'));
    if (minted.did !== did || minted.base_url !== baseUrl) throw new Error('minted identity locator mismatch');
    commitment = verifyFetched({ wireBin, directory, logPath, documentPath });
    } else {
    const result = wire(wireBin, 'webvh-verify-log', { did, log_path: logPath, profile: 'service' });
    if (!result.verified || result.entry_count < 1) throw new Error('current service history is not verified');
    const entries = readFileSync(logPath, 'utf8').split(/\r?\n/).filter(line => line.trim()).map(line => JSON.parse(line));
    const last = entries.at(-1);
    const document = JSON.parse(readFileSync(documentPath, 'utf8'));
    if (entries.length !== result.entry_count || canonical(wireBin, document) !== canonical(wireBin, last.state) || document.id !== did) throw new Error('current document differs from verified history');
    commitment = { did, method_history_head: wire(wireBin, 'sha256-canonical-json', { value: last }).digest, version_id: result.head_version_id, expected_service_id: result.did_core_id };
    }
  }
  const document = JSON.parse(readFileSync(documentPath, 'utf8'));
  const services = (document.service ?? []).filter(service => service.type === 'ArkretService');
  if (services.length !== 1 || services[0].serviceKind !== 'directory_service' || services[0].serviceEndpoint !== baseUrl || new URL(baseUrl).protocol !== 'https:') throw new Error('verified DID does not identify this HTTPS Directory endpoint');
  if ((expectedHistoryHead && expectedHistoryHead !== commitment.method_history_head) || (expectedVersionId && expectedVersionId !== commitment.version_id)) throw new Error('configured Directory commitment does not match verified current history');
  // Missing SDK projection is an error: an older CLI cannot grant fallback trust.
  if (!commitment.expected_service_id?.startsWith('ak:did_core:')) throw new Error('SDK projection output is missing; rebuild the prepared wire CLI');
  writeFileSync(path.join(evidenceDirectory, 'verified.json'), JSON.stringify(commitment, null, 2), 'utf8');
  return commitment;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const command = process.argv[2];
  const input = JSON.parse(readFileSync(0, 'utf8'));
  const output = command === 'mint' ? await mint(input)
    : command === 'verify-fetched' ? verifyFetched(input)
    : command === 'verify-remote' ? await verifyRemote(input)
    : command === 'assert-describe' ? { service_id: assertDescribe(input) }
    : (() => { throw new Error(`unknown command ${command}`); })();
  process.stdout.write(`${JSON.stringify(output)}\n`);
}
