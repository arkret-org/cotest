import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { mint, verifyFetched, assertDescribe, wire } from '../lib/joint-flagon-identity.mjs';

const root = process.env.COTEST_FLAGON_TEST_ROOT ?? os.tmpdir();
mkdirSync(root, { recursive: true });
const directory = mkdtempSync(path.join(root, 'pure-cli-'));
const wireBin = process.env.COTEST_WIRE_BIN;
if (!wireBin) throw new Error('COTEST_WIRE_BIN must select the actual prepared wire CLI');
const repoRoot = process.env.COTEST_REPO_ROOT ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
let built;
test('SDK mints and verifies exact Directory WebVH originals at /webvh/flagon', async () => {
  built = await mint({ wireBin, repoRoot, baseUrl: 'https://flagon.local.host:44443', directory: path.join(directory, 'identity') });
  assert.match(built.did, /:webvh:flagon$/);
  assert.equal(built.log_path.replaceAll('\\', '/').endsWith('/webvh/flagon/did.jsonl'), true);
  const commitment = verifyFetched({ wireBin, directory: path.join(directory, 'identity'), logPath: built.log_path, documentPath: built.document_path });
  assert.equal(commitment.did, built.did);
  assert.equal(commitment.version_id, built.version_id);
  assert.match(commitment.method_history_head, /^sha256:[0-9a-f]{64}$/);
  assert.notEqual(commitment.method_history_head, built.version_id);
  writeFileSync(path.join(directory, 'result.json'), JSON.stringify({ built, commitment }, null, 2));
});
test('a tampered signed entry fails the actual SDK verifier', () => {
  const entry = JSON.parse(readFileSync(built.log_path, 'utf8'));
  entry.state.service[0].serviceEndpoint = 'https://wrong.local.host:44443';
  const tampered = path.join(directory, 'tampered.did.jsonl');
  writeFileSync(tampered, `${JSON.stringify(entry)}\n`);
  assert.throws(() => verifyFetched({ wireBin, directory: path.join(directory, 'identity'), logPath: tampered, documentPath: built.document_path }), /webvh-verify-log failed/);
});
test('verified log cannot authenticate a different fetched document', () => {
  const document = JSON.parse(readFileSync(built.document_path, 'utf8'));
  document.service[0].serviceKind = 'station';
  const documentPath = path.join(directory, 'wrong.did.json');
  writeFileSync(documentPath, JSON.stringify(document));
  assert.throws(() => verifyFetched({ wireBin, directory: path.join(directory, 'identity'), logPath: built.log_path, documentPath }), /differs from exact minted original/);
});
test('owned mint rejects plaintext endpoint and an existing identity directory', async () => {
  await assert.rejects(mint({ wireBin, repoRoot, baseUrl: 'http://127.0.0.1:44443', directory: path.join(directory, 'http') }), /canonical HTTPS/);
  await assert.rejects(mint({ wireBin, repoRoot, baseUrl: 'https://flagon.local.host:44443', directory: path.join(directory, 'identity') }), /already exists/);
});
test('describe gate checks exact independently projected core/commitment/role', () => {
  // This gate unit case does not claim actual HTTP or SDK projection credit;
  // the added SDK CLI projection is validated after its next genuine build.
  const commitment = { did: built.did, method_history_head: 'sha256:' + 'a'.repeat(64), version_id: built.version_id, expected_service_id: 'ak:did_core:web:directory.example' };
  const describe = { service_id: commitment.expected_service_id, service_kind: 'directory_service', service_resolution: { ...commitment }, supported_operation_bundles: ['ak.operation_bundle.directory_service.public_read.v1'] };
  assert.equal(assertDescribe({ describe, commitment }), commitment.expected_service_id);
  for (const patch of [
    { service_id: built.did }, { service_id: 'ak:did_core:web:other.example' },
    { service_kind: 'station' }, { supported_operation_bundles: [] },
    { service_resolution: { ...commitment, method_history_head: 'sha256:' + 'b'.repeat(64) } },
  ]) assert.throws(() => assertDescribe({ describe: { ...describe, ...patch }, commitment }), /independently verified identity/);
  assert.throws(() => assertDescribe({ describe, commitment, expectedServiceId: 'ak:did_core:web:other.example' }), /independently verified identity/);
});

test('verified WebVH and pure SDK projection agree without describe self-assertion', () => {
  const verified = wire(wireBin, 'webvh-verify-log', { did: built.did, log_path: built.log_path, profile: 'service' });
  const projected = wire(wireBin, 'project-did-core-id', { did: built.did });
  assert.match(verified.did_core_id, /^ak:did_core:/);
  assert.equal(verified.did_core_id, projected.did_core_id);
  assert.notEqual(verified.did_core_id, built.did);
  assert.match(wire(wireBin, 'project-did-core-id', { did: 'did:web:directory.example' }).did_core_id, /^ak:did_core:/);
  assert.throws(() => wire(wireBin, 'project-did-core-id', { did: 'not-a-did' }), /failed/);
});
test('explicit no-history document locator comes from the actual SDK adapter', () => {
  assert.equal(wire(wireBin, 'did-web-document-url', { did: 'did:web:directory.example' }).document_url, 'https://directory.example/.well-known/did.json');
  assert.equal(wire(wireBin, 'did-web-document-url', { did: 'did:web:directory.example%3A8443:directory' }).document_url, 'https://directory.example:8443/directory/did.json');
  assert.throws(() => wire(wireBin, 'did-web-document-url', { did: built.did }), /failed/);
});
