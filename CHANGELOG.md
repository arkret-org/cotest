# Changelog

All notable changes to **cotest** are documented here.

## R3.4 — Spec sync 2026-05-31 (cokret-spec @ c2848a4)

- Synced protocol-facing names and fixtures to `c2848a4`: event envelope schema naming, `_ids` grant constraints, accountability principal vocabulary, `ck:rtc_participant:` media participants, agent session start fields, and key-backup signature algorithm naming where applicable.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## R3.3 — Spec sync 2026-05-28 (cokret-spec @ cced4b8)

### CXP-0011 — object addressing + `cx.directory.resolve_target`

- OA-COT-1..4: eleven `cx.vector.object_addressing.*` conformance vectors over the SDK's object-addressing surface (`contrix_core::model::*`), driven from `src/conformance/object_addressing_vectors.rs`:
  - **OA-COT-1 (grammar, 4 cases)** — `web+cokret:` ⇄ HTTPS-fragment equivalence (both envelopes parse to the same `ParsedAddress`; built landing/scheme forms round-trip); realm-only / flow / message hierarchy forms; fail-closed on unknown keyword, wrong hierarchy order, and flow|message missing `via`; `<realm>` disambiguation (UUIDv7 → `RealmRef::RealmId`, dotted/domain → `RealmRef::Alias`).
  - **OA-COT-2 (`target_digest` stability, 3 cases)** — adding/removing `via` / `action` / `tok` / `lt` on the same identity tuple does NOT change the digest; switching `flow_id` / `message_id` (or promoting realm→flow→message) DOES; the digest is computed over the OMITTED-key canonical shape, not a `null` shape.
  - **OA-COT-3 (scope confusion, 2 cases)** — an object-A token fails `verify_token_target` against an object-B address (cross-object replay rejected); the token's `link_type` wins over a disagreeing URL `lt` hint via the `effective_link_type` argument (no reference→invite upgrade).
  - **OA-COT-4 (`resolve_target` shape, 2 cases)** — `DirectoryResolveTargetResBody` deserializes the §9.1 common fields (`as_of`, `source_refs`, `via_services`) + `target_kind`; a realm target carries `realm_preview` (pure (de)serialization, no live server).
- OA-COT-5: `test_oa_cot_5_share_resolve_open_live` scaffold — live share→resolve→open integration gated `#[ignore]` pending teabay's flow/message access-gate.
- Consumes the base SDK at `../cokret-rust-sdk` @ cf6b640 via local path-deps (no SDK changes).

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## R3 — Spec sync 2026-05-27 (cokret-spec @ b47ff6ec)

- VECT-MB-1..9: nine `cx.vector.media_binding.*` conformance vectors covering oldest-membership focus selection, write-once `session_focus`, minimal token shape (`participant_binding.v1`, TTL `<=600s`), unauthorised issuer, missing / invalid binding, unknown focus type, MLS-Exporter-only E2EE key source, unrecognised participant identity, and recording artifacts via Cokret blob.
- VECT-AG-1..5 / VECT-SC-1..4: full agent (`provision`, `pairing_expiry`, `controller_lifecycle`, `act_on_behalf`, `session_grant.replay`) and sidecar (`ensure_idempotent`, `eligibility_states`, `existence_privacy`, `multi_agent_publish`) vector sets.
- VECT-CUR-1 / VECT-CUR-2 / FIX-1: cursor `core` vector now stateful and `stateless_profile` vector profile-gated; `fixtures/` extended with `recovery-policy.json`, `recovery-receipt.json`, `agent_payloads.json`.
- TEST-1..6: scaffolded scenarios for agent FSM (active → paused → active → deactivated terminal), media token exchange happy + 4 negative paths, `accountable_principals.strict_reject` profile toggle, cursor opaque round-trip, recovery policy state machine, and handle homograph reject — live integrations gated `#[ignore]` pending R3.1 server wiring.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## [Unreleased]

### CXP-0007 Circle primitive rollout (cokret-spec `2b0d70d`)

- **Fixed (P2F.1)** — purged `discussion_realm_ref` from the e2e
  Playwright suite (`e2e/tests/messaging/discussion-upgrade.spec.ts`),
  fixture comments (`tests/fixtures/composite_state_subject_fixture.json`,
  `tests/fixtures/read_receipt_policy_fixture.json`),
  `src/conformance/wire_model.rs` and `src/round23_rules.rs`. The
  discussion-upgrade flow now promotes to a Circle via `scope_circle_id`
  (per CXP-0007); the legacy field is hard-rejected.
- **Added (P2F.2)** — `src/circle_rules.rs` literal-scanner module with
  four rules: `DiscussionRealmRef` (hard-reject), `UnknownCircleEventKind`
  (allowlist of 7 event kinds + 6 capability actions),
  `EffectiveScopeCircleMissingId`, and
  `ConfidentialDiscussionEndpointsNotFlow`. Wired into the harness via
  `literal_scanner::scan_tree_circle`. Supports the `CIRCLE-ALLOW` marker
  comment for self-tests and migration notes.
- **Added (P2F.3)** — seven Rust scenarios under `src/scenarios/circle/`:
  `create_circle`, `member_strict_subset`, `flow_scope_visibility`,
  `effective_scope_mismatch`, `confidential_discussion_relation`,
  `cap_action_grant`, `error_code_paths`. Each is driven from
  `tests/circle_scenarios.rs`; scenarios are pure SDK-level and need no
  live server.
- **Added (P2F.4)** — four directory / anti-enumeration scenarios under
  `src/scenarios/directory/`: `anti_enumeration_buckets` (member-count
  bucket ladder), `latency_jitter` (response-latency floor + jitter
  envelope), `takedown_audit_log` (canonical reason set + audit-row
  validator), `circle_not_indexed` (teabay MUST DROP Circle-scoped
  events). Driven from `tests/directory_scenarios.rs`.
- **Added (P2F.5)** — `.github/workflows/ci.yml` (fmt / clippy / test /
  typos / deny / audit, plus Playwright matrix list across chromium /
  firefox / webkit) and `.github/workflows/integration.yml` (nightly
  cross-project bring-up of soland + coauth + floria with
  journey-coverage.json artifact upload). No release artefacts produced.
- Notes: version number unchanged; this round is not released.

### Round R4 — protocol review closures (2026-05-20, cokret-spec `2a4d39b..a77b995`)

Closes the round-4 protocol-review commits on the test-harness surface.
See [`../_todos.md`](../_todos.md) for the workstream context.

- **Added** 12 new executable security-closure vectors from
  `cokret-spec/spec/v1/artifacts/fixtures/security-closure-vectors.json`:
  `federation.idempotency_after_key_revoke`,
  `webrtc.media_plaintext_downgrade`,
  `identity_link.eager_invalidation`,
  `identity_link.policy_tightening_invalidation`,
  `late_key_recovery.removed_actor`,
  `invite.oob_code_entropy`, `invite.failure_indistinguishable`,
  `consent.scope_cascade`, `consent.cache_invalidation`,
  `sync.soft_fail_reconcile`, `lattice.lww_open_set`,
  `e2ee_relaxed.window_exceeds_ceiling`.
- **Added** security-closure runner contract:
  `{given_state, operation}` → assertions on
  `{transcript, expected_state_transition, expected_external_response,
  expected_audit_reason}`.
- **Added** schema-validation-fixture runner: positive + negative cases
  exercised against `schema_ref`.
- **Added** drift-validator allowlist updates — capability action
  `cx.morph.create`; error codes `delivery_binding_stale` /
  `delivery_binding_handed_over` / `historical_only`; `ck:space:` joins
  the `object_ref` id-kind context; new schema `$defs`
  (`EventsSubscribeFrame`, `SnapshotBootstrap`,
  `EventsFrontier{Account,Federation,AnonymousHealth}Response`,
  `PolicyCheck{Request,Response}`, `FederationServiceBindingRef`,
  `EventsSubmit{Batch,Federation}Request`, `third_party_invite`,
  `space_state_transition_payload`, `space_object_tombstone_payload`).
- **Added** 4 new literal-scanner rules: any `did:` whose method segment
  contains `.` / `-` / `_` / `:`; any `cx.events.subscribe` string-payload
  use (must be `EventsSubscribeFrame`); any `cx.cross_signing.publish`
  payload missing `expected_previous_generation`; any
  `compute_audit_policy_version_digest` call with fewer than 4 arguments.

### Added

Track cokret-spec round 2+3 (commit range `f3c3bad..2a4d39b`, principal
commit `8b7978d spec: round 2+3 cleanup`):

- **15 new error codes** baseline-loaded from
  `cokret-spec/spec/v1/artifacts/registry/error-code-registry.json`:
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
- **2 new typed ID kinds**: `ck:trust_domain:<scope>` and
  `ck:appeal:<uuidv7>` validated by the id-kind registry suite.
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
  - `discussion_space_ref` flagged as legacy of `discussion_realm_ref`
    (R1.x rename); both names are now forbidden — CXP-0007 replaces them
    with `scope_circle_id` on the modern wire.
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
  `cokret-spec` artifacts path; cotest does not mirror them locally,
  so the round 2+3 refreshes (cursor `ck:realm:` ids and 2099
  timestamps) are picked up automatically.
- Several new scenarios are stubs with `// TODO(round23-T<XX>)` markers
  pending downstream fixture wiring (soland reducers, SDK helpers, SFU
  governance binding harness, OOB code lockout harness). The scenario
  function signatures and expected error codes are present so the
  harness compiles and the contract surface is pinned for the
  implementer projects.

### Updated (round 2+3 scenario execution pass)

Wired the 10 new round 2+3 scenarios so the **wire-level checks**
execute as real `#[tokio::test]` assertions against the SDK error
code constants (`contrix_core::ERROR_CODE_*`) instead of returning
`Ok(())` unconditionally. The full live-server e2e branches remain
`#[ignore]` with a clear `TODO(round23-T<XX>)` for the docker /
fixture wiring follow-up. Net test-count delta: lib went from
**36 → 53** passing tests; 7 new `#[ignore]` stubs surface in the
ignored count.

Scenarios that now execute real wire-level assertions
(SDK constant ↔ cotest pin ↔ registry alignment):

- `anchor_canonical_no_self_reference` — builds an Anchor via the
  SDK, calls `anchor_canonical_bytes`, asserts the canonical bytes
  exclude `"id":`, `"anchorer_sig"`, and `"jws"`, and recomputes the
  id via `compute_anchor_id` (T01, fully executable).
- `e2ee_relaxed_window_negative` (both branches, T09).
- `cross_signing_reset_cross_domain` (both branches, T08) — also
  exercises `TypedTrustDomainId::new` + `EventId::new` round-trip.
- `moderation_appeal_flow_end_to_end` (T06) — also exercises
  `TypedAppealId::new` round-trip.
- `late_key_recovery_removed_actor` (T16).
- `media_plaintext_downgrade_no_governance_binding` (T12).
- `presign_blob_fail_closed` (both branches, T11) — plus a header
  pin test for `Cache-Control` / `Referrer-Policy`.
- `federation_idempotency_after_revoke` (T14) — pins
  `HISTORICAL_ONLY_MARKER` literal.
- `oob_code_entropy_and_lockout` (both branches, T15) — pins the
  22-char entropy floor, 3-strike threshold, 50ms timing budget,
  and unified `not_found` reason.
- `consent_revoke_scope_any_cascade` (T17) — pins the
  `superseded_by_any_revoke` marker and the 5 cache-invalidation
  channels.

Scenarios still gated `#[ignore]` (need live-server fixtures):

- `full_soland_late_recovery_end_to_end` (T16)
- `full_soland_sodmin_appeal_flow` (T06)
- `full_soland_sfu_plaintext_binding_check` (T12)
- `full_soland_presign_fail_closed` (T11)
- `full_federation_replay_after_key_revoke` (T14)
- `full_coauth_three_strike_lockout` (T15)
- `full_soland_consent_cascade_and_cache_invalidation` (T17)

Also added `tests/round23_tree_scan.rs` — a manual `#[ignore]`
driver that walks the cokret-dev sibling projects (soland, floria,
chime, yougen, teabay, coauth, sodmin, starid, cokret-rust-sdk,
e2e, logos) with `scan_tree_round23` and prints residual structural
findings. Invoke with `cargo test --test round23_tree_scan --
--ignored --nocapture`.

Baseline note: `cargo test --test conformance_fixtures` still
reports the **70 passed / 1 failed** pre-existing
`artifact_registry_suite` failure (a `ck:trust_domain:did.webvh.example`
non-UUIDv7 payload in a cokret-spec fixture file from before this
pass). That failure is unrelated to the round 2+3 scenario wiring
and is not introduced or fixed here.
