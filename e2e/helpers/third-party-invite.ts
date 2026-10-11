// Third-party invite (3PID) proof helpers.
//
// sync/third-party-invites.md §3-4: a verification service signs a
// `binding_proof` attesting "token holder == subject DID"; the claimant signs a
// `subject_proof` attesting "I agree to be bound by this specific binding_proof".
// coland's reducer (apply_invites.rs) + the detached-proof verifier
// (invite_claim_proofs.rs) check both signatures with real Ed25519 keys resolved
// through the DID resolver, so these fixtures MUST produce genuine signatures
// over the exact canonical transcripts.
//
// The verification-service fixture owns a submitted DID document. The subject
// proof uses the accepted native WebVH update key (third-party-invites.md
// §4.3). The outer Event's PCR device producer is independent of that authority.

import { generateKeyPairSync, sign as nodeSign, type KeyObject } from "node:crypto";
import {
  accountActorId,
  canonicalJson,
  projectDidToCoreId,
  sha256CanonicalJson,
} from "./coland-api";
import { sdkInviteSubjectProof } from "./coland-api/wire-client";
import {
  ed25519PrivateKeySeedB64url,
  encodeEd25519PubkeyMultibase,
  rawEd25519PublicKey,
} from "./encoding";

// Domain separators — must match coland invite_claim_proofs.rs verbatim,
// trailing "\n" included.
const BINDING_PROOF_TRANSCRIPT_DOMAIN = "ak.invite.claim.binding_proof.v1\n";
const INVITE_AUDIENCE = "arkret.invite.claim";

export type DidKeyIdentity = {
  did: string;
  verificationMethod: string;
  publicKeyMultibase: string;
  signingSeedB64url: string;
  privateKey: KeyObject;
};

export type InviteSubjectIdentity = {
  did: string;
  verificationMethod: string;
  rootPublicKeyMultibase: string;
  recoveryKey: string;
};

export type ThirdPartyInviteCell = {
  // Event-derived-id contract (event-kind-registry.json declares
  // `id_source="event_derived"` for `ak.invite.third_party`): the Invite id is
  // a retype of the accepted Event id, so it only exists once the invite
  // Event is accepted — the submit helper fills it in.
  inviteId?: string;
  realmId: string;
  expiresAt: string;
  tokenCommitment: string;
  thirdPartyInvite: Record<string, unknown>;
};

function cellInviteId(cell: ThirdPartyInviteCell): string {
  if (!cell.inviteId) {
    throw new Error(
      "invite id is a retype of the accepted ak.invite.third_party Event id; submit the invite Event before building claim proofs",
    );
  }
  return cell.inviteId;
}

// Mint a fresh `did:key` Ed25519 identity. The single verification method is
// `did:key:<mb>#<mb>`, exactly what DidKeyResolver synthesizes. The multibase
// (`z` + base58btc(0xed01 ‖ key)) is rendered by the shared `encoding.ts`
// authority so did:key generation can never drift from coland's decoder.
export function generateDidKeyIdentity(): DidKeyIdentity {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const multibase = encodeEd25519PubkeyMultibase(rawEd25519PublicKey(publicKey));
  const did = `did:key:${multibase}`;
  return {
    did,
    verificationMethod: `${did}#${multibase}`,
    publicKeyMultibase: multibase,
    signingSeedB64url: ed25519PrivateKeySeedB64url(privateKey),
    privateKey,
  };
}

function ed25519SignatureB64url(privateKey: KeyObject, payload: Buffer): string {
  return nodeSign(null, payload, privateKey).toString("base64url");
}

function transcriptBytes(domain: string, transcript: unknown): Buffer {
  return Buffer.concat([
    Buffer.from(domain, "utf8"),
    Buffer.from(canonicalJson(transcript), "utf8"),
  ]);
}

// `sha256:` + canonical_sha256({expires_at, invite_id, realm_id,
// third_party_invite}) — coland invite_record_digest
// (projection.rs invite_claim_proof_context). `invite_id` is the
// Event-derived retype of the accepted invite Event; `expires_at` is the
// rfc3339-seconds form stored on the invite cell, which for events submitted
// through `ak.invite.third_party` is exactly the `expires_at` the test wrote.
function inviteRecordDigest(cell: ThirdPartyInviteCell): string {
  return `sha256:${sha256CanonicalJson({
    expires_at: cell.expiresAt,
    invite_id: cellInviteId(cell),
    realm_id: cell.realmId,
    third_party_invite: cell.thirdPartyInvite,
  })}`;
}

// Build a `ak.invite.third_party` payload whose `third_party_invite` the test fully
// controls (so the claim transcripts can be reconstructed byte-for-byte). The
// commitment is `sha256:<hex>` over an opaque per-invite secret — the plaintext
// 3PID never appears, satisfying the privacy invariant.
//
// The payload is the closed `invite_third_party_create_payload` form
// (event-payload.schema.json: required ["third_party_invite", "expires_at"],
// additionalProperties false): the Invite id derives from the accepted Event
// id and MUST NOT be carried, so no invite/invite_id field exists here.
export function buildThirdPartyInvitePayload(args: {
  realmId: string;
  verificationService: DidKeyIdentity;
  tokenCommitment: string;
  tokenSaltId?: string;
  expiresAt: string;
  displayNameHint?: string;
}): { payload: Record<string, unknown>; cell: ThirdPartyInviteCell } {
  const thirdPartyInvite: Record<string, unknown> = {
    oob_code_kind: "offline_token",
    token_commitment: args.tokenCommitment,
    token_salt_id: args.tokenSaltId ?? "salt-3pid-e2e-001",
    token_entropy_bits: 128,
    // invite.schema.json types this as did_core_id, and coland compares it
    // byte-for-byte against the Realm allowlist and the binding_proof's
    // verification_id, so every carrier uses the core-id spelling.
    verification_id: projectDidToCoreId(args.verificationService.did),
    verification_public_key: args.verificationService.verificationMethod,
    max_claims: 1,
  };
  if (args.displayNameHint) {
    thirdPartyInvite.display_name_hint = args.displayNameHint;
  }
  const payload = {
    third_party_invite: thirdPartyInvite,
    expires_at: args.expiresAt,
  };
  return {
    payload,
    cell: {
      realmId: args.realmId,
      expiresAt: args.expiresAt,
      tokenCommitment: args.tokenCommitment,
      thirdPartyInvite,
    },
  };
}

// Sign the `binding_proof` exactly as coland reconstructs it: the unsigned proof
// object (no `signature`/`sig`) wrapped in the domain-separated transcript that
// binds invite_id / realm_id / subject_id / token_commitment / claim_nonce /
// invite_digest / verification_id.
export function signBindingProof(args: {
  cell: ThirdPartyInviteCell;
  verificationService: DidKeyIdentity;
  subjectId: string;
  claimNonce: string;
  bindingExpiresAt: string;
}): Record<string, unknown> {
  const serviceId = projectDidToCoreId(args.verificationService.did);
  const subjectAccountId = accountActorId(args.subjectId).account_id;
  const unsigned = {
    verification_id: serviceId,
    verification_method: args.verificationService.verificationMethod,
    subject_account_id: subjectAccountId,
    realm_id: args.cell.realmId,
    audience: INVITE_AUDIENCE,
    claim_nonce: args.claimNonce,
    expires_at: args.bindingExpiresAt,
  };
  const transcript = transcriptBytes(BINDING_PROOF_TRANSCRIPT_DOMAIN, {
    audience: INVITE_AUDIENCE,
    binding_proof: unsigned,
    claim_nonce: args.claimNonce,
    invite_digest: inviteRecordDigest(args.cell),
    invite_id: cellInviteId(args.cell),
    realm_id: args.cell.realmId,
    subject_account_id: subjectAccountId,
    token_commitment: args.cell.tokenCommitment,
    verification_id: serviceId,
  });
  return {
    ...unsigned,
    signature: ed25519SignatureB64url(
      args.verificationService.privateKey,
      transcript,
    ),
  };
}

// Sign the `subject_proof` over `ak.invite.claim.subject_proof.v1` — semantics:
// "I agree to be bound by this exact binding_proof from this exact service".
export function signSubjectProof(args: {
  cell: ThirdPartyInviteCell;
  subject: InviteSubjectIdentity;
  verificationServiceDid: string;
  bindingProof: Record<string, unknown>;
  claimNonce: string;
}): Record<string, unknown> {
  const subjectAccountId = accountActorId(
    projectDidToCoreId(args.subject.did),
  ).account_id;
  // This transcript is security-critical and has a typed canonical builder in
  // the SDK. Drive that single authority instead of maintaining a second
  // hand-written JSON projection in the Playwright harness.
  return sdkInviteSubjectProof({
    subjectAccountId,
    inviteId: cellInviteId(args.cell),
    realmId: args.cell.realmId,
    tokenCommitment: args.cell.tokenCommitment,
    claimNonce: args.claimNonce,
    verificationId: projectDidToCoreId(args.verificationServiceDid),
    bindingProof: args.bindingProof,
    verificationMethod: args.subject.verificationMethod,
    subjectDid: args.subject.did,
    rootPublicKeyMultibase: args.subject.rootPublicKeyMultibase,
    recoveryKey: args.subject.recoveryKey,
  });
}

// Build the full `ak.invite.claim` payload from a signed binding/subject pair.
export function buildClaimPayload(args: {
  cell: ThirdPartyInviteCell;
  subjectId: string;
  claimNonce: string;
  bindingProof: Record<string, unknown>;
  subjectProof: Record<string, unknown>;
}): Record<string, unknown> {
  return {
    invite_id: cellInviteId(args.cell),
    subject_account_id: accountActorId(args.subjectId).account_id,
    token_commitment: args.cell.tokenCommitment,
    claim_nonce: args.claimNonce,
    binding_proof: args.bindingProof,
    subject_proof: args.subjectProof,
  };
}
