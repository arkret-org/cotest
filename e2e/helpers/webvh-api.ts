// did:webvh rotation helpers (S9 / identity/webvh-rotation.md).
//
// These mirror, byte-for-byte, the inception + rotation entry construction that
// coauth's `services/soland_webvh.rs` and soland's
// `routing/identity/did/webvh.rs` + `webvh_validation.rs` perform, so the
// genesis SCID, per-entry hash chain, controller proof (eddsa-jcs-2022) and
// witness attestation all verify against a live soland:
//
//   - SCID  = sha256-multihash-multibase of the canonical-JCS genesis skeleton
//             with `{SCID}` placeholders and `proof`/`versionId`/`witness`
//             stripped (derive_webvh_scid_from_skeleton).
//   - hash  = sha256-multihash-multibase of the canonical-JCS entry with
//             `proof` + `versionId` stripped (webvh_entry_hash_multibase).
//   - proof = ed25519 signature (eddsa-jcs-2022) over the canonical-JCS entry
//             with `proof` stripped, `verificationMethod = did:key:<mb>#<mb>`
//             (build_proof / verify_webvh_log_proof).
//   - witness = ed25519 signature over the canonical-JCS entry with `proof`,
//             `witness`, and `versionId` stripped. The entry hash includes
//             `witness[]`, so the witness transcript cannot include the final
//             `versionId` without creating a cycle.
//
// Canonical JSON is the project's JCS profile (sorted keys, integer-only
// numbers, NFC) — the same `canonicalJson` soland's
// `arkret_sdk::canonical::canonical_json_bytes` implements.

import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  type KeyObject,
  sign,
} from "node:crypto";
import {
  expect,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import { canonicalBytes, expectJsonOk } from "./soland-api";
import { base58btcEncode, encodeEd25519PubkeyMultibase } from "./encoding";

export { base58btcEncode, encodeEd25519PubkeyMultibase };

const WEBVH_SCID_PLACEHOLDER = "{SCID}";
const WEBVH_METHOD_VERSION = "did:webvh:1.0";

export type WebvhKey = {
  /// raw 32-byte ed25519 public key
  publicKey: Buffer;
  /// node KeyObject used to produce detached ed25519 signatures
  privateKey: KeyObject;
  /// `z…` base58btc multibase of the multicodec-prefixed public key
  multibase: string;
};

export function generateWebvhKey(): WebvhKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) {
    throw new Error("ed25519 JWK missing x coordinate");
  }
  const raw = Buffer.from(jwk.x, "base64url");
  return {
    publicKey: raw,
    privateKey,
    multibase: encodeEd25519PubkeyMultibase(raw),
  };
}

function sha256MultihashMultibase(bytes: Buffer): string {
  const digest = createHash("sha256").update(bytes).digest();
  // multihash: sha2-256 (0x12) + length 32 (0x20) + digest.
  const multihash = Buffer.concat([Buffer.from([0x12, 0x20]), digest]);
  return `z${base58btcEncode(multihash)}`;
}

function stripForHash(entry: Record<string, unknown>): Record<string, unknown> {
  const clone = { ...entry };
  delete clone.proof;
  delete clone.versionId;
  return clone;
}

export function entryHashMultibase(entry: Record<string, unknown>): string {
  return sha256MultihashMultibase(canonicalBytes(stripForHash(entry)));
}

/// Sign an entry (with `proof` stripped) under eddsa-jcs-2022 and return the
/// DataIntegrityProof object. `verificationMethod` mirrors coauth's
/// `did:key:<mb>#<mb>` shape so the fragment carries the signing key.
export function buildEntryProof(
  entry: Record<string, unknown>,
  signer: WebvhKey,
): Record<string, unknown> {
  const payloadEntry = { ...entry };
  delete payloadEntry.proof;
  const signature = sign(null, canonicalBytes(payloadEntry), signer.privateKey);
  return {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: `did:key:${signer.multibase}#${signer.multibase}`,
    proofPurpose: "assertionMethod",
    proofValue: `z${base58btcEncode(signature)}`,
  };
}

/// soland's `embedded_webvh_authority`: host (with `%3A<port>` for the DID
/// method authority, literal `:<port>` for URLs).
export function webvhAuthority(baseUrl: string): {
  methodAuthority: string;
  httpsAuthority: string;
} {
  const url = new URL(baseUrl);
  const host = url.hostname;
  if (!host.includes(".")) {
    throw new Error(
      `webvh host must contain a dot for did:webvh: ${host}`,
    );
  }
  if (url.port) {
    return {
      methodAuthority: `${host}%3A${url.port}`,
      httpsAuthority: `${host}:${url.port}`,
    };
  }
  return { methodAuthority: host, httpsAuthority: host };
}

export function formatWebvhDid(
  methodAuthority: string,
  scid: string,
  localId: string,
): string {
  return `did:webvh:${scid}:${methodAuthority}:webvh:${localId}`;
}

export type GenesisInput = {
  baseUrl: string;
  localId: string;
  didKey: WebvhKey;
  updateKey: WebvhKey;
  alsoKnownAs?: string[];
  serviceEndpoint?: string;
  versionTime?: string;
  /// genesis-declared recovery keys (key-management.md §3.3) — emergency
  /// rotations may then be signed by one of these instead of the controller.
  recoveryKeys?: string[];
  /// witnesses + threshold this DID requires (resolver counts attestations
  /// against this quorum).
  witnessKeys?: string[];
  witnessThreshold?: number;
  /// genesis-declared organization governance threshold (identity-did.md §8).
  governance?: { threshold: number; eligibleMethods: string[] };
};

export type BuiltEntry = {
  did: string;
  scid: string;
  versionId: string;
  localId: string;
  entry: Record<string, unknown>;
  didDocument: Record<string, unknown>;
};

function genesisDidDocument(
  did: string,
  didKeyId: string,
  didKey: WebvhKey,
  alsoKnownAs: string[],
  serviceEndpoint: string,
): Record<string, unknown> {
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    verificationMethod: [
      {
        id: didKeyId,
        type: "Multikey",
        controller: did,
        publicKeyMultibase: didKey.multibase,
      },
    ],
    authentication: [didKeyId],
    assertionMethod: [didKeyId],
    alsoKnownAs,
    service: [
      {
        id: `${did}#soland`,
        type: "ArkretPrincipalServer",
        serviceEndpoint,
      },
    ],
  };
}

/// Build the inception entry (SCID, versionId, controller proof). Mirrors
/// soland `embedded_webvh_register`.
export function buildGenesisEntry(input: GenesisInput): BuiltEntry {
  const { methodAuthority, httpsAuthority } = webvhAuthority(input.baseUrl);
  void httpsAuthority;
  const versionTime = input.versionTime ?? new Date().toISOString();
  const serviceEndpoint =
    input.serviceEndpoint ?? input.baseUrl.replace(/\/$/, "");
  const placeholderDid = formatWebvhDid(
    methodAuthority,
    WEBVH_SCID_PLACEHOLDER,
    input.localId,
  );
  const placeholderKeyId = `${placeholderDid}#did-key-1`;
  const skeletonDoc = genesisDidDocument(
    placeholderDid,
    placeholderKeyId,
    input.didKey,
    input.alsoKnownAs ?? [],
    serviceEndpoint,
  );
  const parameters: Record<string, unknown> = {
    scid: WEBVH_SCID_PLACEHOLDER,
    method: WEBVH_METHOD_VERSION,
    updateKeys: [input.updateKey.multibase],
  };
  if (input.recoveryKeys?.length) {
    parameters.recoveryKeys = input.recoveryKeys;
  }
  if (input.witnessKeys?.length) {
    parameters.witnesses = input.witnessKeys.map((key) => ({
      publicKeyMultibase: key,
    }));
    parameters.witness_threshold =
      input.witnessThreshold ?? input.witnessKeys.length;
  }
  if (input.governance) {
    parameters.governance = {
      threshold: {
        required: input.governance.threshold,
        eligible_methods: input.governance.eligibleMethods,
      },
    };
  }
  const entrySkeleton: Record<string, unknown> = {
    versionId: `0-${WEBVH_SCID_PLACEHOLDER}`,
    versionTime,
    parameters,
    state: skeletonDoc,
  };
  const scid = sha256MultihashMultibase(canonicalBytes(entrySkeleton));
  const did = formatWebvhDid(methodAuthority, scid, input.localId);
  const realised = JSON.parse(
    JSON.stringify(entrySkeleton).split(WEBVH_SCID_PLACEHOLDER).join(scid),
  ) as Record<string, unknown>;
  const versionHash = entryHashMultibase(realised);
  const versionId = `1-${versionHash}`;
  realised.versionId = versionId;
  realised.proof = [buildEntryProof(realised, input.updateKey)];
  return {
    did,
    scid,
    versionId,
    localId: input.localId,
    entry: realised,
    didDocument: realised.state as Record<string, unknown>,
  };
}

export type RotationInput = {
  did: string;
  scid: string;
  prevVersionId: string;
  prevDidDocument: Record<string, unknown>;
  /// the previous entry's `parameters.updateKeys` (distinct from the
  /// document's verificationMethod). Required for `keepControl` refreshes so
  /// the entry re-declares the SAME updateKeys and soland sees no rotation.
  prevUpdateKeys?: string[];
  newUpdateKey: WebvhKey;
  /// key that signs the rotation entry: the previous update key (normal
  /// controller rotation), a recovery key (emergency), or one or more
  /// governance keys.
  signers: WebvhKey[];
  /// When true the entry keeps the previous document + updateKeys unchanged
  /// (a witness / metadata refresh, NOT a control rotation). soland's
  /// `is_rotation_entry` then returns false, so this entry is governed by the
  /// degraded-window rule rather than the immediate rotation fail-closed rule.
  keepControl?: boolean;
  versionTime?: string;
  /// witness signing keys. Their multibase is declared in
  /// `parameters.witnesses` and they sign the `witness[]` attestation. When
  /// `witnessKeys` is omitted it is derived from these.
  witnesses?: WebvhKey[];
  witnessKeys?: string[];
  witnessThreshold?: number;
  governance?: { threshold: number; eligibleMethods: string[] };
  recoveryKeys?: string[];
};

/// Build a rotation entry linked to the previous head. The new document keeps
/// the same id but swaps in the new controlling key; `updateKeys` advances to
/// the new update key.
///
/// Ordering matters and mirrors soland: the `witness[]` attestation is signed
/// over the proof+witness+versionId-stripped body, then the versionId hash is
/// computed over the body INCLUDING `witness[]` (soland strips only proof +
/// versionId), and finally the controller `proof[]` is signed over the body
/// including `witness[]` + `versionId`.
export function buildRotationEntry(input: RotationInput): BuiltEntry {
  const seq = parseInt(input.prevVersionId.split("-")[0], 10) + 1;
  const versionTime = input.versionTime ?? new Date().toISOString();
  const witnessKeys =
    input.witnessKeys ?? input.witnesses?.map((key) => key.multibase);
  const prevDoc = input.prevDidDocument;
  let newDocument: Record<string, unknown>;
  let updateKeys: string[];
  if (input.keepControl) {
    if (!input.prevUpdateKeys?.length) {
      throw new Error("keepControl requires prevUpdateKeys");
    }
    newDocument = { ...prevDoc };
    updateKeys = input.prevUpdateKeys;
  } else {
    const newKeyId = `${input.did}#did-key-${seq}`;
    newDocument = {
      ...prevDoc,
      verificationMethod: [
        {
          id: newKeyId,
          type: "Multikey",
          controller: input.did,
          publicKeyMultibase: input.newUpdateKey.multibase,
        },
      ],
      authentication: [newKeyId],
      assertionMethod: [newKeyId],
    };
    updateKeys = [input.newUpdateKey.multibase];
  }
  const parameters: Record<string, unknown> = {
    scid: input.scid,
    method: WEBVH_METHOD_VERSION,
    updateKeys,
  };
  if (input.recoveryKeys?.length) {
    parameters.recoveryKeys = input.recoveryKeys;
  }
  if (witnessKeys?.length) {
    parameters.witnesses = witnessKeys.map((key) => ({
      publicKeyMultibase: key,
    }));
    parameters.witness_threshold = input.witnessThreshold ?? witnessKeys.length;
  }
  if (input.governance) {
    parameters.governance = {
      threshold: {
        required: input.governance.threshold,
        eligible_methods: input.governance.eligibleMethods,
      },
    };
  }
  const body: Record<string, unknown> = {
    versionTime,
    previousVersionId: input.prevVersionId,
    parameters,
    state: newDocument,
  };
  if (input.witnesses?.length) {
    body.witness = input.witnesses.map((witness) =>
      buildWitnessProof(body, witness),
    );
  }
  const versionHash = entryHashMultibase(body);
  const versionId = `${seq}-${versionHash}`;
  body.versionId = versionId;
  body.proof = input.signers.map((signer) => buildEntryProof(body, signer));
  return {
    did: input.did,
    scid: input.scid,
    versionId,
    localId: input.did.split(":webvh:").pop() ?? "",
    entry: body,
    didDocument: newDocument,
  };
}

/// A witness proof signs the entry with `proof`, `witness`, and `versionId`
/// stripped (matching soland `verify_one_witness_proof`). soland's resolver
/// verifies the `witness[]` array (distinct from the controller `proof[]`) and
/// counts each distinct valid signer whose multibase is declared in
/// `parameters.witnesses` toward the witness quorum.
export function buildWitnessProof(
  entry: Record<string, unknown>,
  witness: WebvhKey,
): Record<string, unknown> {
  const payloadEntry = { ...entry };
  delete payloadEntry.proof;
  delete payloadEntry.witness;
  delete payloadEntry.versionId;
  const signature = sign(null, canonicalBytes(payloadEntry), witness.privateKey);
  return {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: `did:web:witness.example#${witness.multibase}`,
    proofValue: `z${base58btcEncode(signature)}`,
  };
}

// ── HTTP wrappers ─────────────────────────────────────────────────────────

export function webvhRegistrationBearer(): string {
  return process.env.COTEST_WEBVH_REGISTRATION_BEARER ?? "joint-e2e-webvh-registration";
}

export function bearerHeaders(): Record<string, string> {
  return { authorization: `Bearer ${webvhRegistrationBearer()}` };
}

export async function registerWebvhGenesis(
  request: APIRequestContext,
  baseUrl: string,
  built: BuiltEntry,
  input: GenesisInput,
): Promise<Record<string, unknown>> {
  const response = await request.post(
    `${baseUrl.replace(/\/$/, "")}/_soland/root/identity/webvh/register`,
    {
      headers: bearerHeaders(),
      data: {
        local_id: input.localId,
        did_public_key_multibase: input.didKey.multibase,
        update_public_key_multibase: input.updateKey.multibase,
        also_known_as: input.alsoKnownAs ?? [],
        version_time: (built.entry.versionTime as string) ?? undefined,
        proof: (built.entry.proof as unknown[])[0],
        ...(input.recoveryKeys?.length
          ? { recovery_keys: input.recoveryKeys }
          : {}),
        ...(input.governance
          ? {
              governance: {
                threshold: {
                  required: input.governance.threshold,
                  eligible_methods: input.governance.eligibleMethods,
                },
              },
            }
          : {}),
      },
    },
  );
  return await expectJsonOk(response, `register webvh genesis ${built.did}`);
}

export async function rawRotateWebvh(
  request: APIRequestContext,
  baseUrl: string,
  did: string,
  built: BuiltEntry,
): Promise<APIResponse> {
  return await request.post(
    `${baseUrl.replace(/\/$/, "")}/_soland/root/identity/webvh/rotate`,
    {
      headers: bearerHeaders(),
      data: { did, log_entry: built.entry },
    },
  );
}

export async function rotateWebvh(
  request: APIRequestContext,
  baseUrl: string,
  did: string,
  built: BuiltEntry,
): Promise<Record<string, unknown>> {
  const response = await rawRotateWebvh(request, baseUrl, did, built);
  return await expectJsonOk(response, `rotate webvh ${did}`);
}

export async function rawResolveDid(
  request: APIRequestContext,
  baseUrl: string,
  did: string,
): Promise<APIResponse> {
  return await request.post(
    `${baseUrl.replace(/\/$/, "")}/_arkret/root/identity/resolve`,
    { data: { did } },
  );
}

export async function resolveDid(
  request: APIRequestContext,
  baseUrl: string,
  did: string,
): Promise<{
  did_document: { did: string; document: Record<string, unknown> };
  key_log_head?: string | null;
  seq?: number;
  method_evidence?: Record<string, unknown>;
}> {
  const response = await rawResolveDid(request, baseUrl, did);
  return await expectJsonOk(response, `resolve did ${did}`);
}

export async function fetchDidLog(
  request: APIRequestContext,
  baseUrl: string,
  did: string,
): Promise<Array<Record<string, unknown>>> {
  const response = await request.get(
    `${baseUrl.replace(/\/$/, "")}/_arkret/root/identity/log?did=${encodeURIComponent(did)}`,
  );
  const body = await expectJsonOk<{ events?: Array<Record<string, unknown>> }>(
    response,
    `fetch did log ${did}`,
  );
  return body.events ?? [];
}

/// Count verificationMethod fragments in a resolved document — used to assert
/// the controlling key advanced after a rotation.
export function documentControlKeys(
  document: Record<string, unknown>,
): string[] {
  const methods = Array.isArray(document.verificationMethod)
    ? (document.verificationMethod as Array<Record<string, unknown>>)
    : [];
  return methods
    .map((method) => method.publicKeyMultibase)
    .filter((value): value is string => typeof value === "string");
}

export { expect };
