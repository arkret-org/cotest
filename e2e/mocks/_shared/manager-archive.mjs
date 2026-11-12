// Privileged test-manager custody, independent from Device/authoring storage.
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { replaceStateFileSync } from "./atomic-state.mjs";
import { canonicalJson } from "./http.mjs";

const schema = "cotest.mock_applet_manager_archive_encrypted.v1";
function heldKey(entry) {
  const value = entry.backup_private_key_base64url;
  if (typeof value !== "string" || Buffer.from(value, "base64url").length !== 32 ||
      Buffer.from(value, "base64url").toString("base64url") !== value) {
    throw new Error("native manager archive has no complete held private key");
  }
  return value;
}
function readKey(path) {
  if (!path || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
    throw new Error("native manager archive key is unavailable");
  }
  const key = readFileSync(path);
  if (key.length !== 32) throw new Error("native manager archive key must be 32 bytes");
  return key;
}
function independentKey(keyFile, authoringKeyFile) {
  const key = readKey(keyFile);
  if (key.equals(readKey(authoringKeyFile))) {
    throw new Error("native archive cannot use the generic authoring key");
  }
  return key;
}
function persist(file, key, state) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(schema));
  const ciphertext = Buffer.concat([cipher.update(canonicalJson(state)), cipher.final()]);
  const envelope = { schema, algorithm: "A256GCM", nonce: nonce.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"), tag: cipher.getAuthTag().toString("base64url") };
  mkdirSync(dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporary, canonicalJson(envelope), { flag: "wx", mode: 0o600, flush: true });
  replaceStateFileSync(temporary, file);
}
function load(file, key) {
  if (!lstatSync(file).isFile() || lstatSync(file).isSymbolicLink()) {
    throw new Error("native manager archive is unavailable");
  }
  const envelope = JSON.parse(readFileSync(file, "utf8"));
  if (envelope.schema !== schema || envelope.algorithm !== "A256GCM") {
    throw new Error("native manager archive envelope is invalid");
  }
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.nonce, "base64url"));
  decipher.setAAD(Buffer.from(schema));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
  const state = JSON.parse(Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64url")), decipher.final(),
  ]).toString("utf8"));
  if (!Array.isArray(state.entries)) throw new Error("native manager archive index is invalid");
  for (const entry of state.entries) heldKey(entry);
  return state;
}

// Only the fresh-run setup may initialize a vault. Runtime never resets loss.
export function initializeManagerArchive(file, keyFile, authoringKeyFile) {
  if (existsSync(file)) throw new Error("native manager archive already exists");
  persist(file, independentKey(keyFile, authoringKeyFile), { entries: [] });
}

export class ManagerArchive {
  #file;
  #keyFile;
  #authoringKeyFile;
  constructor(file, keyFile, authoringKeyFile) {
    if (!file || !keyFile || !authoringKeyFile) throw new Error("native manager archive is not configured");
    this.#file = file;
    this.#keyFile = keyFile;
    this.#authoringKeyFile = authoringKeyFile;
    load(this.#file, independentKey(keyFile, authoringKeyFile));
  }
  prepareInception(request, build) {
    if (!request || typeof request.base_url !== "string" || !request.base_url ||
        typeof request.local_id !== "string" || !request.local_id ||
        Object.hasOwn(request, "content_backup_private_key_b64url")) {
      throw new Error("native manager inception request is invalid");
    }
    const key = independentKey(this.#keyFile, this.#authoringKeyFile);
    const state = load(this.#file, key);
    const subject = canonicalJson([request.base_url, request.local_id]);
    const digest = createHash("sha256").update(canonicalJson(request)).digest("hex");
    let entry = state.entries.find(entry => entry.subject === subject);
    if (entry && entry.request_digest !== digest) throw new Error("native manager inception conflicts with its original intent");
    if (!entry) {
      entry = { subject, request_digest: digest, backup_private_key_base64url: randomBytes(32).toString("base64url") };
      state.entries.push(entry);
      // The real private key is physically retained before its public declaration.
      persist(this.#file, key, state);
    }
    const inception = build({ ...request, content_backup_private_key_b64url: heldKey(entry) });
    if (!inception || typeof inception.did !== "string" || !inception.entry || !inception.didDocument) {
      throw new Error("native manager inception kernel returned no original");
    }
    if (entry.inception && canonicalJson(entry.inception) !== canonicalJson(inception)) {
      throw new Error("held native archive key differs from its public original");
    }
    if (!entry.inception) {
      entry.inception = inception;
      persist(this.#file, key, state);
    }
    return structuredClone(entry.inception);
  }
  bindActor(inception, actor, originalPublicKey, derivePublicKey) {
    const key = independentKey(this.#keyFile, this.#authoringKeyFile);
    const state = load(this.#file, key);
    const entry = state.entries.find(entry => entry.inception?.did === inception.did);
    if (!entry || typeof derivePublicKey !== "function" ||
        derivePublicKey(heldKey(entry)) !== originalPublicKey ||
        canonicalJson(entry.inception) !== canonicalJson(inception) ||
        (entry.actor_id && canonicalJson(entry.actor_id) !== canonicalJson(actor))) {
      throw new Error("native manager archive does not hold this exact original actor");
    }
    if (!entry.actor_id) {
      entry.actor_id = actor;
      persist(this.#file, key, state);
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [operation, file, keyFile, authoringKeyFile] = process.argv.slice(2);
  if (operation !== "initialize" || !file || !keyFile || !authoringKeyFile) {
    throw new Error("expected initialize and three explicit fixture paths");
  }
  initializeManagerArchive(file, keyFile, authoringKeyFile);
}
