import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { ManagerArchive, initializeManagerArchive } from "./manager-archive.mjs";
import { canonicalJson } from "./http.mjs";

const root = fileURLToPath(new URL("../../../artifacts/tool-tests/", import.meta.url));
function fixture() {
  mkdirSync(root, { recursive: true });
  const directory = mkdtempSync(resolve(root, "manager-archive-"));
  const file = resolve(directory, "archive.json");
  const key = resolve(directory, "archive.key");
  const authoring = resolve(directory, "authoring.key");
  writeFileSync(key, randomBytes(32), { mode: 0o600 });
  writeFileSync(authoring, randomBytes(32), { mode: 0o600 });
  const clear = () => {
    assert.equal(dirname(directory), resolve(root));
    assert.ok(basename(directory).startsWith("manager-archive-"));
    rmSync(directory, { recursive: true, force: true });
  };
  const read = () => {
    const envelope = JSON.parse(readFileSync(file, "utf8"));
    const decipher = createDecipheriv("aes-256-gcm", readFileSync(key), Buffer.from(envelope.nonce, "base64url"));
    decipher.setAAD(Buffer.from(envelope.schema));
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64url")), decipher.final()]).toString());
  };
  const rewrite = state => {
    const envelope = JSON.parse(readFileSync(file, "utf8"));
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", readFileSync(key), nonce);
    cipher.setAAD(Buffer.from(envelope.schema));
    const ciphertext = Buffer.concat([cipher.update(canonicalJson(state)), cipher.final()]);
    writeFileSync(file, canonicalJson({ ...envelope, nonce: nonce.toString("base64url"),
      ciphertext: ciphertext.toString("base64url"), tag: cipher.getAuthTag().toString("base64url") }));
  };
  return { file, key, authoring, clear, read, rewrite };
}

function derivePublicKey(privateKey) {
  const key = createPrivateKey({ key: Buffer.concat([
    Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.from(privateKey, "base64url"),
  ]), format: "der", type: "pkcs8" });
  return createPublicKey(key).export({ format: "jwk" }).x;
}

// Storage units treat the SDK callback output as opaque. Real DID/HPKE and
// original creation validation run separately in the Rust fixture tests.
const request = { base_url: "https://manager.fixture", local_id: "subject", root_seed_b64url: "authoring-input" };
const original = { did: "opaque-storage-subject", entry: { original: true }, didDocument: { source: "SDK callback" } };

test("fresh-run initialization CLI creates one vault and refuses to replace it", () => {
  const f = fixture();
  try {
    const command = [fileURLToPath(new URL("./manager-archive.mjs", import.meta.url)),
      "initialize", f.file, f.key, f.authoring];
    assert.equal(spawnSync(process.execPath, command, { windowsHide: true }).status, 0);
    assert.equal(f.read().entries.length, 0);
    new ManagerArchive(f.file, f.key, f.authoring);
    const before = readFileSync(f.file);
    assert.notEqual(spawnSync(process.execPath, command, { windowsHide: true }).status, 0);
    assert.ok(readFileSync(f.file).equals(before));
  } finally { f.clear(); }
});

test("archive flushes its independent real private key before calling the inception kernel", () => {
  const f = fixture();
  try {
    initializeManagerArchive(f.file, f.key, f.authoring);
    const vault = new ManagerArchive(f.file, f.key, f.authoring);
    let privateKey;
    const result = vault.prepareInception(request, input => {
      privateKey = input.content_backup_private_key_b64url;
      assert.equal(Buffer.from(privateKey, "base64url").length, 32);
      const stored = f.read().entries[0];
      assert.ok(stored.content_backup_private_key_b64url === privateKey, "private key must already be on disk");
      assert.equal(stored.inception, undefined);
      return original;
    });
    assert.ok(canonicalJson(result) === canonicalJson(original));
    assert.ok(!readFileSync(f.file, "utf8").includes(privateKey));
    assert.ok(!canonicalJson(result).includes(privateKey));
  } finally { f.clear(); }
});

test("reopened archive replays exact public inception and refuses changed intent without writing", () => {
  const f = fixture();
  try {
    initializeManagerArchive(f.file, f.key, f.authoring);
    new ManagerArchive(f.file, f.key, f.authoring).prepareInception(request, () => original);
    const before = readFileSync(f.file);
    const reopened = new ManagerArchive(f.file, f.key, f.authoring);
    const result = reopened.prepareInception(request, input => {
      assert.ok(input.content_backup_private_key_b64url === f.read().entries[0].content_backup_private_key_b64url);
      return original;
    });
    assert.ok(canonicalJson(result) === canonicalJson(original));
    assert.ok(readFileSync(f.file).equals(before));
    assert.throws(() => reopened.prepareInception({ ...request, root_seed_b64url: "changed" }, () => original));
    assert.ok(readFileSync(f.file).equals(before));
  } finally { f.clear(); }
});

test("generic authoring key cannot initialize or unlock the independent archive", () => {
  const f = fixture();
  try {
    assert.throws(() => initializeManagerArchive(f.file, f.authoring, f.authoring));
    assert.equal(existsSync(f.file), false);
    initializeManagerArchive(f.file, f.key, f.authoring);
    assert.throws(() => new ManagerArchive(f.file, f.authoring, f.key));
    assert.throws(() => initializeManagerArchive(f.file, f.key, f.authoring));
  } finally { f.clear(); }
});

test("runtime refuses lost ciphertext or unlock key rather than resetting custody", () => {
  for (const missing of ["file", "key"]) {
    const f = fixture();
    try {
      initializeManagerArchive(f.file, f.key, f.authoring);
      const vault = new ManagerArchive(f.file, f.key, f.authoring);
      vault.prepareInception(request, () => original);
      unlinkSync(f[missing]);
      assert.throws(() => vault.prepareInception(request, () => original));
      assert.equal(existsSync(f[missing]), false);
    } finally { f.clear(); }
  }
});

test("only the exact held original can bind once to its complete actor coordinate", () => {
  const f = fixture();
  try {
    initializeManagerArchive(f.file, f.key, f.authoring);
    const vault = new ManagerArchive(f.file, f.key, f.authoring);
    vault.prepareInception(request, () => original);
    const actor = { realm: "opaque-realm", principal: original.did };
    const publicKey = derivePublicKey(f.read().entries[0].content_backup_private_key_b64url);
    vault.bindActor(original, actor, publicKey, derivePublicKey);
    const before = readFileSync(f.file);
    new ManagerArchive(f.file, f.key, f.authoring).bindActor(original, actor, publicKey, derivePublicKey);
    assert.ok(readFileSync(f.file).equals(before));
    assert.throws(() => vault.bindActor({ ...original, entry: { substituted: true } }, actor, publicKey, derivePublicKey));
    assert.throws(() => vault.bindActor(original, { ...actor, realm: "other-realm" }, publicKey, derivePublicKey));
    assert.ok(readFileSync(f.file).equals(before));
  } finally { f.clear(); }
});

test("cached public originals cannot replace missing or substituted physical archive keys", () => {
  for (const fault of ["missing", "substituted"]) {
    const f = fixture();
    try {
      initializeManagerArchive(f.file, f.key, f.authoring);
      const vault = new ManagerArchive(f.file, f.key, f.authoring);
      vault.prepareInception(request, () => original);
      const state = f.read();
      const publicKey = derivePublicKey(state.entries[0].content_backup_private_key_b64url);
      if (fault === "missing") delete state.entries[0].content_backup_private_key_b64url;
      else state.entries[0].content_backup_private_key_b64url = randomBytes(32).toString("base64url");
      f.rewrite(state);
      const before = readFileSync(f.file);
      assert.throws(() => vault.bindActor(original, { realm: "opaque-realm" }, publicKey, derivePublicKey));
      assert.ok(readFileSync(f.file).equals(before));
    } finally { f.clear(); }
  }
});


test("a fresh Node process restores the exact encrypted private half before declaration", () => {
  const f = fixture();
  try {
    initializeManagerArchive(f.file, f.key, f.authoring);
    new ManagerArchive(f.file, f.key, f.authoring).prepareInception(request, () => original);
    const publicKey = derivePublicKey(f.read().entries[0].content_backup_private_key_b64url);
    const before = readFileSync(f.file);
    const module = new URL("./manager-archive.mjs", import.meta.url).href;
    const program = `import {ManagerArchive} from ${JSON.stringify(module)};
      import {createPrivateKey,createPublicKey} from "node:crypto";
      const vault=new ManagerArchive(...process.argv.slice(1));
      vault.prepareInception(${JSON.stringify(request)}, input=>{
        const privateKey=createPrivateKey({key:Buffer.concat([Buffer.from("302e020100300506032b656e04220420","hex"),
          Buffer.from(input.content_backup_private_key_b64url,"base64url")]),format:"der",type:"pkcs8"});
        process.stdout.write(createPublicKey(privateKey).export({format:"jwk"}).x);
        return ${JSON.stringify(original)};
      });`;
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", program,
      f.file, f.key, f.authoring], { windowsHide: true, encoding: "utf8" });
    assert.equal(child.status, 0, "cold manager process must restore the held private half");
    assert.equal(child.stdout, publicKey);
    assert.ok(readFileSync(f.file).equals(before));
  } finally { f.clear(); }
});

test("author callback alone receives the held private input and binds the exact original", () => {
  const f = fixture();
  try {
    initializeManagerArchive(f.file, f.key, f.authoring);
    const vault = new ManagerArchive(f.file, f.key, f.authoring);
    vault.prepareInception(request, () => original);
    const publicKey = derivePublicKey(f.read().entries[0].content_backup_private_key_b64url);
    const actor = { realm_id: "storage-only-realm", principal_id: original.did };
    const outcome = { create_event: { payload: { actor_id: actor,
      recovery: { content_backup_recipient: { public_key_base64url: publicKey } } } } };
    let callbackCalled = false;
    const result = vault.authorOriginal(original, input => {
      callbackCalled = true;
      assert.ok(input.content_backup_private_key_b64url === f.read().entries[0].content_backup_private_key_b64url);
      assert.equal(Object.keys(input).join(","), "content_backup_private_key_b64url");
      return outcome;
    }, derivePublicKey);
    assert.ok(callbackCalled);
    assert.ok(canonicalJson(result) === canonicalJson(outcome));
    assert.ok(!canonicalJson(result).includes(f.read().entries[0].content_backup_private_key_b64url));
    const before = readFileSync(f.file);
    assert.throws(() => vault.authorOriginal({ ...original, entry: { changed: true } },
      () => { throw new Error("must not reach callback"); }, derivePublicKey));
    assert.throws(() => vault.authorOriginal(original,
      () => ({ create_event: { payload: { actor_id: actor,
        recovery: { content_backup_recipient: { public_key_base64url: "substituted" } } } } }), derivePublicKey));
    assert.ok(readFileSync(f.file).equals(before));
  } finally { f.clear(); }
});

test("damaged private archive JSON fails without echo or custody reset", () => {
  const f = fixture();
  try {
    initializeManagerArchive(f.file, f.key, f.authoring);
    const canary = "private-archive-json-must-not-be-echoed";
    writeFileSync(f.file, `{"private":"${canary}`);
    const before = readFileSync(f.file);
    assert.throws(() => new ManagerArchive(f.file, f.key, f.authoring), error => {
      assert.ok(!error.message.includes(canary));
      return true;
    });
    assert.ok(readFileSync(f.file).equals(before));
  } finally { f.clear(); }
});


test("different base and local intent retain separate physical keys in the one manager archive", () => {
  const f = fixture();
  try {
    initializeManagerArchive(f.file, f.key, f.authoring);
    const vault = new ManagerArchive(f.file, f.key, f.authoring);
    for (const [base, local] of [["https://one.fixture", "bot"], ["https://two.fixture", "bot"], ["https://one.fixture", "ghost"]]) {
      vault.prepareInception({ ...request, base_url: base, local_id: local },
        () => ({ ...original, did: `${base}/${local}` }));
    }
    const entries = f.read().entries;
    assert.equal(entries.length, 3);
    const publics = entries.map(entry => derivePublicKey(entry.content_backup_private_key_b64url));
    assert.equal(new Set(publics).size, 3);
    new ManagerArchive(f.file, f.key, f.authoring);
  } finally { f.clear(); }
});
