// Principal did:webvh inception fixture construction.
//
// Every byte of the entry is built by the SDK through the `cotest-wire`
// bridge: SCID derivation, the whole-entry `{SCID}` substitution
// (identity-did.md §3.4.4), the entry hash and the `eddsa-jcs-2022` proof.
// The harness deliberately owns no webvh construction of its own — a
// second implementation here is exactly how a dialect drift starts.
//
// This helper only emits the current cold-root entry-0 shape. The root and
// next root stay in method parameters. Device authorization is intentionally
// absent: the DID is only the identity/root-rotation anchor.

import { generateKeyPairSync, type KeyObject } from "node:crypto";
import type { APIRequestContext } from "@playwright/test";
import { canonicalJson, cotestWire, expectJsonOk } from "./soland-api";
import {
  ed25519PrivateKeySeedB64url,
  encodeEd25519PubkeyMultibase,
} from "./encoding";

export type WebvhKey = {
  publicKey: Buffer;
  privateKey: KeyObject;
  multibase: string;
};

export type WebvhGenesisInput = {
  baseUrl: string;
  localId: string;
  rootKey: WebvhKey;
  nextRootKey: WebvhKey;
  document: (did: string) => Record<string, unknown>;
  versionTime?: string;
};

export type BuiltWebvhGenesis = {
  did: string;
  scid: string;
  versionId: string;
  entry: Record<string, unknown>;
  didDocument: Record<string, unknown>;
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

/// The preliminary `did:webvh:{SCID}:…` a genesis DID document is authored
/// against. The SDK owns the DID <-> hosting-authority mapping.
export function webvhPlaceholderId(baseUrl: string, localId: string): string {
  return cotestWire<{ did: string; method_authority: string }>(
    "webvh-placeholder-did",
    { base_url: baseUrl, local_id: localId },
  ).did;
}

export function buildWebvhGenesisEntry(
  input: WebvhGenesisInput,
): BuiltWebvhGenesis {
  const placeholderId = webvhPlaceholderId(input.baseUrl, input.localId);
  return cotestWire<BuiltWebvhGenesis>("webvh-genesis", {
    base_url: input.baseUrl,
    local_id: input.localId,
    root_seed_b64url: ed25519PrivateKeySeedB64url(input.rootKey.privateKey),
    next_root_public_key_multibase: input.nextRootKey.multibase,
    version_time: input.versionTime,
    document: input.document(placeholderId),
  });
}

export async function submitPrincipalGenesisEntry(
  request: APIRequestContext,
  baseUrl: string,
  built: BuiltWebvhGenesis,
): Promise<void> {
  const response = await request.post(
    `${baseUrl.replace(/\/$/, "")}/_arkret/root/identity/submit-did-operation`,
    {
      headers: { "content-type": "application/json" },
      data: canonicalJson({
        did: built.did,
        did_method: "webvh",
        seq: 1,
        operation: built.entry,
      }),
    },
  );
  await expectJsonOk(response, `submit principal inception ${built.did}`);
}
