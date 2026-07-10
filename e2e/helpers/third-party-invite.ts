// Third-party invite (3PID) proof helpers.
//
// sync/third-party-invites.md §3-4: a verification service signs a
// `binding_proof` attesting "token holder == subject DID"; the claimant signs a
// `subject_proof` attesting "I agree to be bound by this specific binding_proof".
// soland's reducer (apply_invites.rs) + the detached-proof verifier
// (invite_claim_proofs.rs) check both signatures with real Ed25519 keys resolved
// through the DID resolver, so these fixtures MUST produce genuine signatures
// over the exact canonical transcripts.
//
// Both the verification service and the subject use `did:key` DIDs so the key
// material is self-resolving (DidKeyResolver) and no DID-document seeding is
// needed against the joint harness.

import {
  createHash,
  generateKeyPairSync,
  sign as nodeSign,
  type KeyObject,
} from "node:crypto";
import {
  canonicalJson,
  canonicalTimestamp,
  sha256CanonicalJson,
} from "./soland-api";
import { encodeEd25519PubkeyMultibase, rawEd25519PublicKey } from "./encoding";

// Domain separators — must match soland invite_claim_proofs.rs verbatim,
// trailing "\n" included.
const BINDING_PROOF_TRANSCRIPT_DOMAIN = "ak.invite.claim.binding_proof.v1\n";
const SUBJECT_PROOF_TRANSCRIPT_DOMAIN = "ak.invite.claim.subject_proof.v1\n";
const INVITE_AUDIENCE = "arkret.invite.claim";

export type DidKeyIdentity = {
  did: string;
  verificationMethod: string;
  publicKeyMultibase: string;
  privateKey: KeyObject;
};

export type ThirdPartyInviteCell = {
  inviteId: string;
  realmId: string;
  inviter: string;
  expiresAt: string;
  tokenCommitment: string;
  thirdPartyId: Record<string, unknown>;
  joinRuleSnapshot: Record<string, unknown>;
};

// Mint a fresh `did:key` Ed25519 identity. The single verification method is
// `did:key:<mb>#<mb>`, exactly what DidKeyResolver synthesizes. The multibase
// (`z` + base58btc(0xed01 ‖ key)) is rendered by the shared `encoding.ts`
// authority so did:key generation can never drift from soland's decoder.
export function generateDidKeyIdentity(): DidKeyIdentity {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const multibase = encodeEd25519PubkeyMultibase(rawEd25519PublicKey(publicKey));
  const did = `did:key:${multibase}`;
  return {
    did,
    verificationMethod: `${did}#${multibase}`,
    publicKeyMultibase: multibase,
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
// third_party_id}) — soland invite_record_digest. `expires_at` is the
// rfc3339-seconds form stored on the invite cell, which for events submitted
// through `ak.invite.third_party` is exactly the `expires_at` the test wrote.
function inviteRecordDigest(cell: ThirdPartyInviteCell): string {
  return `sha256:${sha256CanonicalJson({
    expires_at: cell.expiresAt,
    invite_id: cell.inviteId,
    realm_id: cell.realmId,
    third_party_id: cell.thirdPartyId,
  })}`;
}

// Build a `ak.invite.third_party` payload whose `third_party_id` the test fully
// controls (so the claim transcripts can be reconstructed byte-for-byte). The
// commitment is `sha256:<hex>` over an opaque per-invite secret — the plaintext
// 3PID never appears, satisfying the privacy invariant.
export function buildThirdPartyInvitePayload(args: {
  inviteId: string;
  realmId: string;
  inviter: string;
  verificationService: DidKeyIdentity;
  tokenCommitment: string;
  tokenSaltId?: string;
  expiresAt: string;
  createdAt?: string;
  joinRule?: string;
  role?: string;
  displayNameHint?: string;
}): { payload: Record<string, unknown>; cell: ThirdPartyInviteCell } {
  const joinRuleSnapshot: Record<string, unknown> = {
    join_rule: args.joinRule ?? "invite",
    role: args.role ?? "member",
  };
  const thirdPartyId: Record<string, unknown> = {
    oob_code_kind: "offline_token",
    token_commitment: args.tokenCommitment,
    token_salt_id: args.tokenSaltId ?? "salt-3pid-e2e-001",
    token_entropy_bits: 128,
    verification_service_did: args.verificationService.did,
    verification_public_key: args.verificationService.verificationMethod,
    max_claims: 1,
  };
  if (args.displayNameHint) {
    thirdPartyId.display_name_hint = args.displayNameHint;
  }
  const createdAt = args.createdAt ?? canonicalTimestamp();
  const payload = {
    invite: {
      id: args.inviteId,
      schema: "ak.schema.invite.v1",
      realm_id: args.realmId,
      inviter: args.inviter,
      third_party_id: thirdPartyId,
      join_rule_snapshot: joinRuleSnapshot,
      state: "pending",
      expires_at: args.expiresAt,
      created_at: createdAt,
    },
  };
  return {
    payload,
    cell: {
      inviteId: args.inviteId,
      realmId: args.realmId,
      inviter: args.inviter,
      expiresAt: args.expiresAt,
      tokenCommitment: args.tokenCommitment,
      thirdPartyId,
      joinRuleSnapshot,
    },
  };
}

// Sign the `binding_proof` exactly as soland reconstructs it: the unsigned proof
// object (no `signature`/`sig`) wrapped in the domain-separated transcript that
// binds invite_id / realm_id / subject_id / token_commitment / claim_nonce /
// invite_digest / verification_service_did.
export function signBindingProof(args: {
  cell: ThirdPartyInviteCell;
  verificationService: DidKeyIdentity;
  subjectId: string;
  claimNonce: string;
  bindingExpiresAt: string;
}): Record<string, unknown> {
  const unsigned = {
    verification_service_did: args.verificationService.did,
    verification_method: args.verificationService.verificationMethod,
    subject_id: args.subjectId,
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
    invite_id: args.cell.inviteId,
    realm_id: args.cell.realmId,
    subject_id: args.subjectId,
    token_commitment: args.cell.tokenCommitment,
    verification_service_did: args.verificationService.did,
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
  subject: DidKeyIdentity;
  verificationServiceDid: string;
  bindingProof: Record<string, unknown>;
  claimNonce: string;
}): Record<string, unknown> {
  const bindingDigest = `sha256:${sha256CanonicalJson(args.bindingProof)}`;
  const transcript = transcriptBytes(SUBJECT_PROOF_TRANSCRIPT_DOMAIN, {
    audience: INVITE_AUDIENCE,
    binding_proof_digest: bindingDigest,
    claim_nonce: args.claimNonce,
    invite_id: args.cell.inviteId,
    realm_id: args.cell.realmId,
    subject_id: args.subject.did,
    token_commitment: args.cell.tokenCommitment,
    verification_service_did: args.verificationServiceDid,
  });
  return {
    verification_method: args.subject.verificationMethod,
    alg: "EdDSA",
    // soland subject_proof transcript_digest = `sha256:<hex>` over the raw
    // transcript byte string (sha256_digest(transcript)), NOT over canonical
    // JSON — hash the bytes directly.
    transcript_digest: `sha256:${createHash("sha256")
      .update(transcript)
      .digest("hex")}`,
    signature: ed25519SignatureB64url(args.subject.privateKey, transcript),
  };
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
    invite_id: args.cell.inviteId,
    subject_id: args.subjectId,
    token_commitment: args.cell.tokenCommitment,
    claim_nonce: args.claimNonce,
    binding_proof: args.bindingProof,
    subject_proof: args.subjectProof,
  };
}
