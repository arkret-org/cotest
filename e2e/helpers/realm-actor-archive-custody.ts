// Private manager fixture custody, not an Arkret wire carrier or a product vault.
// The canonical runner owns this temporary directory and its cleanup.
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
} from "node:crypto";
import {
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

type ArchiveCustodyRecord = {
  base_url: string;
  local_id: string;
  archive_private_jwk: { kty: "OKP"; crv: "X25519"; d: string; x: string };
};

function privatePath(path: string, directory: boolean): void {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())) {
    throw new Error("RealmActor manager fixture custody requires a regular private path");
  }
  if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) {
    throw new Error("RealmActor manager fixture custody must exclude other users");
  }
}

function syncDirectory(path: string): void {
  if (process.platform === "win32") return;
  const descriptor = openSync(path, "r");
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function readRecord(path: string, baseUrl: string, localId: string): ArchiveCustodyRecord {
  privatePath(path, false);
  const descriptor = openSync(path, "r+");
  let raw: string;
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size > 4096) throw new Error("Manager fixture custody exceeds its bound");
    raw = readFileSync(descriptor, "utf8");
    if (Buffer.byteLength(raw, "utf8") > 4096) throw new Error("Manager fixture custody exceeds its bound");
    // Another process can observe the complete record before its creator's
    // fsync. Each reader must establish durability before publishing a key.
    fsyncSync(descriptor);
  } finally { closeSync(descriptor); }
  let record: ArchiveCustodyRecord;
  try { record = JSON.parse(raw) as ArchiveCustodyRecord; }
  catch { throw new Error("Manager fixture private custody cannot be decoded"); }
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw new Error("Manager fixture private custody is not a record");
  }
  const key = record.archive_private_jwk;
  if (record.base_url !== baseUrl || record.local_id !== localId
      || !key || key.kty !== "OKP" || key.crv !== "X25519"
      || typeof key.d !== "string" || typeof key.x !== "string"
      || Buffer.from(key.d, "base64url").length !== 32
      || Buffer.from(key.d, "base64url").toString("base64url") !== key.d
      || Buffer.from(key.x, "base64url").length !== 32
      || Buffer.from(key.x, "base64url").toString("base64url") !== key.x) {
    throw new Error("RealmActor manager fixture custody does not match its original intent");
  }
  let publicJwk;
  try { publicJwk = createPublicKey(createPrivateKey({ key, format: "jwk" })).export({ format: "jwk" }); }
  catch { throw new Error("Manager fixture archive private key cannot be restored"); }
  if (publicJwk.x !== key.x) throw new Error("Manager fixture archive key halves do not match");
  return record;
}

/** Durably create/read the independent private half before inception/SCID publication. */
export function realmActorArchiveCustody(
  baseUrl: string,
  localId: string,
  custodyRoot = process.env.COTEST_PROVISION_CUSTODY_ROOT,
): { privateKeyB64url: string; publicKeyB64url: string } {
  if (!custodyRoot) throw new Error("Canonical runner private custody root is required");
  privatePath(custodyRoot, true);
  const directory = join(custodyRoot, "applet-manager-archive");
  if (!existsSync(directory)) {
    try { mkdirSync(directory, { mode: 0o700 }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    syncDirectory(custodyRoot);
  }
  privatePath(directory, true);
  // Local storage identity only: this hash is never a protocol authority/reference.
  const intent = createHash("sha256").update(JSON.stringify([baseUrl, localId])).digest("hex");
  const path = join(directory, `${intent}.json`);
  if (!existsSync(path)) {
    const pair = generateKeyPairSync("x25519");
    const key = pair.privateKey.export({ format: "jwk" });
    if (!key.d || !key.x) throw new Error("Fresh X25519 manager custody is unavailable");
    const record: ArchiveCustodyRecord = {
      base_url: baseUrl, local_id: localId,
      archive_private_jwk: { kty: "OKP", crv: "X25519", d: key.d, x: key.x },
    };
    let descriptor: number | undefined;
    try {
      descriptor = openSync(path, "wx", 0o600);
      writeFileSync(descriptor, JSON.stringify(record), "utf8");
      fsyncSync(descriptor);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
    }
    syncDirectory(directory);
  }
  // Even a fresh key must be restored from the actual durable record first.
  const record = readRecord(path, baseUrl, localId);
  syncDirectory(directory);
  return { privateKeyB64url: record.archive_private_jwk.d, publicKeyB64url: record.archive_private_jwk.x };
}
