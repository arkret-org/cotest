import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { realmActorArchiveCustody } from "../helpers/realm-actor-archive-custody.ts";

function root(t) {
  const parent = realpathSync(tmpdir());
  const path = mkdtempSync(join(parent, "cotest-manager-archive-"));
  chmodSync(path, 0o700);
  t.after(() => {
    const target = realpathSync(path);
    assert.equal(dirname(target), parent);
    assert.ok(basename(target).startsWith("cotest-manager-archive-"));
    rmSync(target, { recursive: true, force: true });
  });
  return path;
}

test("real independent X25519 custody is durable before the caller can construct inception", (t) => {
  const directory = root(t);
  const first = realmActorArchiveCustody("https://one.example", "bot", directory);
  const files = readdirSync(join(directory, "applet-manager-archive"));
  assert.equal(files.length, 1);
  const stored = JSON.parse(readFileSync(join(directory, "applet-manager-archive", files[0]), "utf8"));
  assert.ok(stored.archive_private_jwk.d === first.privateKeyB64url, "the stored private half matches without printing it");
  assert.equal(stored.archive_private_jwk.x, first.publicKeyB64url);
  const module = new URL("../helpers/realm-actor-archive-custody.ts", import.meta.url).href;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e",
    `import {realmActorArchiveCustody} from ${JSON.stringify(module)};
     const key=realmActorArchiveCustody("https://one.example","bot",process.argv[1]);
     process.stdout.write(key.publicKeyB64url);`, directory], { encoding: "utf8" });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, first.publicKeyB64url);
  const reopened = realmActorArchiveCustody("https://one.example", "bot", directory);
  assert.equal(reopened.publicKeyB64url, first.publicKeyB64url);
  assert.ok(reopened.privateKeyB64url === first.privateKeyB64url, "cold custody preserves the private half");
  assert.notEqual(realmActorArchiveCustody("https://two.example", "bot", directory).publicKeyB64url, first.publicKeyB64url);
  assert.notEqual(realmActorArchiveCustody("https://one.example", "ghost", directory).publicKeyB64url, first.publicKeyB64url);
});

test("missing or damaged existing custody fails closed rather than replacing the original key", (t) => {
  assert.throws(() => realmActorArchiveCustody("https://one.example", "bot", ""));
  const directory = root(t);
  realmActorArchiveCustody("https://one.example", "bot", directory);
  const digest = createHash("sha256").update(JSON.stringify(["https://one.example", "bot"])).digest("hex");
  const path = join(directory, "applet-manager-archive", `${digest}.json`);
  writeFileSync(path, "{}", { mode: 0o600 });
  assert.throws(() => realmActorArchiveCustody("https://one.example", "bot", directory));
  assert.equal(readFileSync(path, "utf8"), "{}");
});

test("a different private half and malformed private JSON are refused without printing secret inputs", (t) => {
  const directory = root(t);
  realmActorArchiveCustody("https://one.example", "bot", directory);
  const path = join(directory, "applet-manager-archive", readdirSync(join(directory, "applet-manager-archive"))[0]);
  const original = JSON.parse(readFileSync(path, "utf8"));
  const other = generateKeyPairSync("x25519").privateKey.export({ format: "jwk" });
  original.archive_private_jwk.d = other.d;
  writeFileSync(path, JSON.stringify(original));
  assert.throws(() => realmActorArchiveCustody("https://one.example", "bot", directory), /halves do not match/);
  const canary = "private-archive-input-must-not-be-echoed";
  writeFileSync(path, `{"archive_private_jwk":"${canary}`);
  assert.throws(() => realmActorArchiveCustody("https://one.example", "bot", directory), error => {
    assert.ok(!error.message.includes(canary));
    return true;
  });
});
