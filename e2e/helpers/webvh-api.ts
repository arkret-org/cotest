// Principal did:webvh inception fixture construction.
//
// This helper only emits the current cold-root entry-0 shape. The root and
// next root stay in method parameters. Device authorization is intentionally
// absent: the DID is only the identity/root-rotation anchor.

import {
  createHash,
  generateKeyPairSync,
  type KeyObject,
  sign,
} from "node:crypto";
import type { APIRequestContext } from "@playwright/test";
import { canonicalBytes, canonicalJson, expectJsonOk } from "./soland-api";
import { base58btcEncode, encodeEd25519PubkeyMultibase } from "./encoding";

const WEBVH_SCID_PLACEHOLDER = "{SCID}";
const WEBVH_METHOD_VERSION = "did:webvh:1.0";

export type WebvhKey = {
  publicKey: Buffer;
  privateKey: KeyObject;
  multibase: string;
};

export type PrincipalGenesisInput = {
  baseUrl: string;
  localId: string;
  rootKey: WebvhKey;
  nextRootKey: WebvhKey;
  alsoKnownAs?: string[];
  serviceEndpoint?: string;
  versionTime?: string;
};

export type BuiltPrincipalGenesis = {
  did: string;
  scid: string;
  versionId: string;
  entry: Record<string, unknown>;
  didDocument: Record<string, unknown>;
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

function sha256MultihashBase58btc(bytes: Buffer): string {
  const digest = createHash("sha256").update(bytes).digest();
  return base58btcEncode(Buffer.concat([Buffer.from([0x12, 0x20]), digest]));
}

function entryHash(
  entry: Record<string, unknown>,
  previousAnchor: string,
): string {
  const preimage: Record<string, unknown> = {
    ...entry,
    versionId: previousAnchor,
  };
  delete preimage.proof;
  return sha256MultihashBase58btc(canonicalBytes(preimage));
}

function buildEntryProof(
  entry: Record<string, unknown>,
  signer: WebvhKey,
): Record<string, unknown> {
  const proofConfig = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: `did:key:${signer.multibase}#${signer.multibase}`,
    proofPurpose: "assertionMethod",
  };
  const document = { ...entry };
  delete document.proof;
  const signingInput = Buffer.concat([
    createHash("sha256").update(canonicalBytes(proofConfig)).digest(),
    createHash("sha256").update(canonicalBytes(document)).digest(),
  ]);
  const signature = sign(null, signingInput, signer.privateKey);
  return {
    ...proofConfig,
    proofValue: `z${base58btcEncode(signature)}`,
  };
}

function webvhMethodAuthority(baseUrl: string): string {
  const url = new URL(baseUrl);
  if (!url.hostname.includes(".")) {
    throw new Error(`webvh host must contain a dot: ${url.hostname}`);
  }
  return url.port ? `${url.hostname}%3A${url.port}` : url.hostname;
}

function formatWebvhDid(
  methodAuthority: string,
  scid: string,
  localId: string,
): string {
  return `did:webvh:${scid}:${methodAuthority}:webvh:${localId}`;
}

function principalDocument(
  did: string,
  input: PrincipalGenesisInput,
): Record<string, unknown> {
  const principalServerService = {
    id: `${did}#soland`,
    type: "ArkretPrincipalServer",
    serviceEndpoint: input.serviceEndpoint ?? input.baseUrl.replace(/\/$/, ""),
  };
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    alsoKnownAs: input.alsoKnownAs ?? [],
    service: [principalServerService],
  };
}

export function buildPrincipalGenesisEntry(
  input: PrincipalGenesisInput,
): BuiltPrincipalGenesis {
  const built = buildWebvhGenesisEntry({
    baseUrl: input.baseUrl,
    localId: input.localId,
    rootKey: input.rootKey,
    nextRootKey: input.nextRootKey,
    document: (did) => principalDocument(did, input),
    versionTime: input.versionTime,
  });
  return built;
}

export function buildWebvhGenesisEntry(
  input: WebvhGenesisInput,
): BuiltWebvhGenesis {
  if (input.rootKey.multibase === input.nextRootKey.multibase) {
    throw new Error("active and next WebVH root keys must be distinct");
  }
  const methodAuthority = webvhMethodAuthority(input.baseUrl);
  const placeholderDid = formatWebvhDid(
    methodAuthority,
    WEBVH_SCID_PLACEHOLDER,
    input.localId,
  );
  const entrySkeleton: Record<string, unknown> = {
    versionId: WEBVH_SCID_PLACEHOLDER,
    versionTime: input.versionTime ?? new Date().toISOString(),
    parameters: {
      scid: WEBVH_SCID_PLACEHOLDER,
      method: WEBVH_METHOD_VERSION,
      updateKeys: [input.rootKey.multibase],
      nextKeyHashes: [
        sha256MultihashBase58btc(
          Buffer.from(input.nextRootKey.multibase, "utf8"),
        ),
      ],
    },
    state: input.document(placeholderDid),
  };
  const scid = sha256MultihashBase58btc(canonicalBytes(entrySkeleton));
  const did = formatWebvhDid(methodAuthority, scid, input.localId);
  const entry = JSON.parse(
    JSON.stringify(entrySkeleton).split(WEBVH_SCID_PLACEHOLDER).join(scid),
  ) as Record<string, unknown>;
  const versionId = `1-${entryHash(entry, scid)}`;
  entry.versionId = versionId;
  entry.proof = [buildEntryProof(entry, input.rootKey)];
  return {
    did,
    scid,
    versionId,
    entry,
    didDocument: entry.state as Record<string, unknown>,
  };
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
