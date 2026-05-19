# Changelog

All notable changes to **cotest** are documented here.

## [Unreleased]

### Added

Track contrix-spec round 2+3 (commit range `f3c3bad..2a4d39b`, principal
commit `8b7978d spec: round 2+3 cleanup`):

- **15 new error codes** baseline-loaded from
  `contrix-spec/spec/v1/artifacts/registry/error-code-registry.json`:
  `relaxed_window_exceeds_ceiling`,
  `e2ee_relaxed_disallowed_in_compliance_profile`,
  `cross_domain_replay_rejected`, `reset_event_id_mismatch`,
  `appeal_overturn_missing_lift`, `appeal_self_review_forbidden`,
  `realm_terminal_state`, `audit_agent_attestation_mismatch`,
  `audit_purpose_mismatch`, `legal_hold_active`, `blob_redacted`,
  `media_plaintext_service_not_authorised`,
  `mls_governance_binding_stale`, `expired_invite_token`,
  `late_recovery_rejected_membership`.
- **4 new event kinds**: `cx.moderation.appeal.{submit,review,decision,close}`
  auto-picked from the event-kind registry.
- **3 new schemas**: `cx.schema.ephemeral_envelope.v1`,
  `cx.schema.moderation_appeal.v1`,
  `cx.schema.attestation_evidence.v1` auto-picked from the schema
  registry.
- **2 new typed ID kinds**: `cx:trust_domain:<scope>` and
  `cx:appeal:<uuidv7>` validated by the id-kind registry suite.
- **2 new capability actions**: `cx.moderation.appeal.submit` and
  `cx.moderation.appeal.review`.
- **`src/round23_rules.rs`** — structural literal-scanner rules:
  - `cx.event_batch_receipt` MUST NOT appear as `Event.kind` (T23).
  - 12 ephemeral-only kinds MUST NOT appear in `cx.events.submit`
    payload (`cx.call.signal`, `cx.presence`, `cx.typing`,
    `cx.receipt.read`, and `cx.key.verification.*`) (T02).
  - `relaxed_window_max_ms > 300_000` in policy components flagged
    (T09).
  - Cursor handle literals shorter than 22 chars flagged (T03).
  - `discussion_space_ref` flagged as renamed to `discussion_realm_ref`
    (R1.x rename).
- **12 new scenarios** under `src/scenarios/`:
  - `late_key_recovery_removed_actor` (T16)
  - `moderation_appeal_flow_end_to_end` (T06)
  - `cross_signing_reset_cross_domain` (cross_domain + event_id mismatch
    variants) (T08)
  - `media_plaintext_downgrade_no_governance_binding` (T12)
  - `oob_code_entropy_and_lockout` (low_entropy + 3-strike variants) (T15)
  - `presign_blob_fail_closed` (legal_hold + redacted variants) (T11)
  - `federation_idempotency_after_revoke` (T14)
  - `e2ee_relaxed_window_negative` (exceeds_ceiling +
    disallowed_in_compliance variants) (T09)
  - `anchor_canonical_no_self_reference` (T01)
  - `consent_revoke_scope_any_cascade` (T17)

### Notes

- Fixtures (`move-anchor-lattice-fixture`, `encoding-fixture`,
  `privacy-security-fixture`) are loaded directly from the
  `contrix-spec` artifacts path; cotest does not mirror them locally,
  so the round 2+3 refreshes (cursor `cx:realm:` ids and 2099
  timestamps) are picked up automatically.
- Several new scenarios are stubs with `// TODO(round23-T<XX>)` markers
  pending downstream fixture wiring (soland reducers, SDK helpers, SFU
  governance binding harness, OOB code lockout harness). The scenario
  function signatures and expected error codes are present so the
  harness compiles and the contract surface is pinned for the
  implementer projects.
