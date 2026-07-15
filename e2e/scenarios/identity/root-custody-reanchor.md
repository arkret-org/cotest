# Identity root cold custody and re-anchor

## Goal

Verify the client-custodied principal identity lifecycle fixed by decision 0010:
the recovery secret is confirmed before publication, every active `did:webvh`
root is cold and pre-rotated, the first PCR/device pair is one atomic unit, and
B-model recovery advances the DID and device generation without allowing the
server or a hot device to become the identity root.

This scenario replaces the obsolete `webvh-rotation` contract. In particular,
a new WebVH entry is signed by the key active in that new entry after it matches
the preceding `nextKeyHashes`; it is never authorized merely by the previous
entry's key. Identity roots and device keys never appear in the principal DID
Document `verificationMethod`.

## Normative anchors

- `identity/key-management.md` §5.0.1–§5.0.7 — cold roots, custody gate,
  pre-rotation, PCR bootstrap, re-anchor, conflict and generation fence
- `identity/identity-did.md` — WebVH SCID/history verification and historical
  resolution
- `crypto-media/device-lifecycle.md` — enrollment-authority model, recovery
  re-anchor, first Seal and device-generation admission
- decision 0010 — identity-root cold custody and inception delegation

## Required strand

1. The client creates a 24-word recovery secret, derives role-separated root,
   recovery-signing and backup-HPKE material, and records a durable draft.
2. Entry 0 cannot be submitted before explicit custody confirmation.
3. The client submits a canonical root-signed entry 0. The DID Document contains
   exactly one enrollment model (A or B), no root, and no device key.
4. A self-principal PCR create signed by `root_0` and the enrollment-authority
   signed first-device authorize are submitted as exactly two ordered Events;
   slot 1 has `actor_seq=1` and `prev_refs=[slot0.event_id]`.
5. Recovery configuration closes only after an accepted role-separated policy
   plus a `did_recovery` first backup, or a verified root-signed offline receipt.
6. A normal root advance activates only the key committed by the previous
   entry, signs with that current key, and commits a distinct next root.
7. B-model recovery submits one atomic root-signed re-anchor and authority-signed
   replacement authorize, bound to the accepted registry head and complete
   pre-fence frontier.
8. The accepted re-anchor advances the device generation; old-generation
   Events/Seals fail closed. Same-height sibling entries/units are all
   quarantined until a higher precommitted authority resolves the conflict.

## Observable assertions

- no recovery phrase/root seed crosses a service API or ordinary application log
- bootstrap split, missing/extra predecessor, wrong authority and partial commit
  have zero durable side effects
- previous-entry proof keys, uncommitted roots, spent-root reuse and mixed A/B
  documents are rejected
- recovery receipt binds both Events and the new DID/device generation
- secret handoff is checkpointed, uses independent authority, rewraps every
  active backup series, advances active pointers, and revokes the old policy key
  only at the end

## Current implementation status

Rust conformance executes the KDF known answers, canonical SDK WebVH history,
typed bootstrap/re-anchor validators, A/B exclusivity and generation fence.
The Rust live atomic PCR test drives the production resolver and admission path
and is a merge gate for this work. Full browser onboarding, recovery re-anchor,
conflict reducer and two-entry secret-handoff strands remain explicit
`test.fixme` promises; fixture-name checks do not count as verification.
