# Regression Review

## 2026-07-22 release-gate baseline drift

Observed while verifying the target-aware Cotest scheduler at Cotest HEAD
`77e5f8ed3e99`. The scheduler executed all 27 configured release-gate tests;
the following failures are product/spec baseline regressions rather than test
selection failures.

### SDK reducer-profile digest is stale

- Severity: P0
- Status: resolved 2026-07-22 by arkret-rust-sdk `84611736`.
- Evidence: `federation_replay_snapshot_and_redaction_contracts_work` receives
  `reducer_profile_mismatch` from Soland.
- Normative value: arkret-spec's current
  `reducer-profile-registry.json` and `federation-fixture.json` both pin
  `sha256:952a4c29fd910fa0f002602d983e621dfbd0b8bce085c8e0030a530290b92d72`.
- Stale generated value: arkret-rust-sdk
  `crates/policy/src/generated/profiles.rs` pins
  `sha256:fe7b320b94f96214842464efa9bdc9f99c54359a8bd9b98a18f24dde04f7426d`.
- Resolution: regenerated the SDK profile constants and embedded artifacts from
  the current spec, rebuilt Soland, and passed the Cotest federation suite with
  the normative `sha256:952a4c29...` digest.

### Inkson mock parity omits Realm founding authority

- Severity: P1
- Status: resolved 2026-07-22.
- Evidence: `inkson_mock_contract_matches_live_soland_baseline` reports drift
  for `events_submit`, `realm_create`, `space_create`, directory search, and
  ephemeral behavior. Live writes fail with `realm_founding_grant_missing`.
- Normative source: `models/realm-and-space.md` section 2.5 requires
  `ak.realm.create` and its closed-form founding grant in one ordered batch.
- Resolution: removed the parity test's duplicate single-event Realm builder
  and reused Cotest's normative Realm bootstrap helper, which submits the
  create event and founding grant as one ordered batch. The live parity test now
  passes without an allowlist entry.

### Morph migration fixture violates Realm actor-chain genesis

- Severity: P1
- Evidence: joint-smoke's additive morph migration receives
  `schema_violation`: `a Realm-scoped actor-chain genesis must use actor_seq=1`.
- Required resolution: derive the migration event's actor sequence and previous
  references from the live Realm actor frontier; a new Realm-scoped chain must
  begin at one.

## 2026-07-22 Deferred MLS Welcome and second-member decrypt regression

- Severity: P0
- Status: resolved and verified together by final focused joint run
  `20260723-034404` (`2 passed (4.0m)`, managed service failures `[]`).
- Evidence: the Realm UI projected two joined members while the administrator
  logged `admission pre-filter blocked`, and the invitee remained at
  `decryption_pending` with no local MLS snapshot. The same session also tried
  the founding-only `device-enroll` endpoint at an existing PCR frontier and
  was correctly rejected by Coauth.
- Root causes:
  1. Inkson treated a missing or mismatched current device signer as permission
     to invoke founding-device enrollment after PCR creation.
  2. MLS admission derived its reconciliation candidates only from the local
     `raw_operations` cursor window and ignored account sync's current
     `members[]` roster hint. The inverse is also unsafe: the hint is not
     accepted membership authority.
  3. Crown-jewel browser tests prepared both users' KeyPackages before invite,
     so they never exercised deferred admission.
  4. Commit and Welcome were separate, non-durable writes, so navigation after
     Commit acceptance could permanently lose the bound Welcome.
  5. The client could send on an old MLS epoch while a complete roster hint
     already showed that its local group was behind.
  6. Joined-history initial sync hid the current pre-join encryption policy,
     making the wire content scheme unknowable after invitee reload.
  7. The joint runner could serve a stale Dioxus debug WASM and the send helper
     masked concrete product failures behind a response timeout.
- Resolution rules:
  1. Founding authorization remains atomic with PCR create; later or mismatched
     devices use explicit pairing/recovery and never call `device-enroll`.
  2. `ak.member.state` interpreted at the accepted Seal/Lattice state remains
     membership authority. `members[]` is only a reconciliation/UI hint:
     `members_limited=true` permits positive retry scheduling but never
     negative/removal claims, while even a complete hint cannot authorize a
     Commit or clear `epoch_update_required` without verified governance proof.
     A limited hint must not erase a joined actor already present in verified
     membership state, and verified state wins any hint conflict.
  3. Device authorization and KeyPackage publication must re-check/retry from
     durable state transitions without reload, re-invite, or an unrelated
     timeline message.
  4. Joint E2E must invite before the second browser publishes a KeyPackage,
     then prove automatic Welcome, bidirectional post-join decrypt, shared
     pre-join history recovery, reload durability, and ciphertext-only storage.
  5. Commit, exact signed Welcome(s), and post-commit snapshot form one durable
     saga. Once Commit is accepted, Welcome material is never terminally
     discarded; retries must preserve its event id and `commit_ref`. CAS,
     signer-generation changes, deterministic rejection, and local snapshot
     persistence failure must retain the immutable saga for explicit repair.
  6. Encrypted sends conservatively pause whenever a complete roster hint
     differs from local MLS membership or the verified content scheme is
     unavailable. Hint agreement alone never replaces the accepted
     governance-binding send gate.
  7. Joined-history filtering may hide pre-join data-plane events, but an active
     member's initial sync must include the latest Realm create/policy security
     baseline needed to validate current encrypted writes.
  8. Joint builds must verify the exact served WASM feature/debug markers.
     Send helpers may retry only an explicit `encryption_transition_pending`
     during a bounded convergence window; every other UI failure must fail
     immediately with its concrete status, and a retry is green only after a
     real accepted ciphertext POST is observed.

## 2026-07-22 Native Agent session accountability drift

- Severity: P0
- Evidence: an Agent provisioned through Soland could pair successfully but
  Coauth rejected every later `agent_key_proof` session with
  `accountability_grant_missing` unless a second implementation-local
  `/_coauth/self/agents/{id}/accountability-grant` record was minted.
- Normative source: `identity/key-management.md` section 3.6.1 requires the
  controller-authored `ak.identity.accountability_grant` Event accepted during
  the two-phase provision operation to remain the protocol truth source.
  `accountability_scope` is governance metadata and MUST NOT become a content
  capability set.
- Resolution: Soland's standard Agent projection now validates the exact
  provisioning accountability Event and its current CAS-register lifecycle;
  Coauth consumes that projection and no longer intersects session content
  scope with its implementation-local accountability table.

## 2026-07-23 Native Agent MLS test evidence overclaim

- Severity: P0
- Status: resolved; report/test classification corrected and an independent live runtime leg added.
- Evidence: `agent_encrypted_realm_member_e2e.rs` used only in-process
  `ArkretMlsIdentity`, `ArkretMlsGroup`, and `MemoryCryptoStore` calls. It made
  no request to Coauth or Soland, did not consume a standard device-message
  queue, and did not persist/replay a durable consume intent, while its test
  name and task report described it as a live end-to-end Agent lifecycle.
- Normative source: `identity/key-management.md` section 3.6.1,
  `crypto-media/encryption-and-audit.md` section 2.6, and
  `crypto-media/device-lifecycle.md` section 9 require the same stable Agent
  device binding across session, KeyPackage, Welcome, durable group-state,
  consume/revoke, and authorization replacement.
- Resolution: reclassified the old executable test as local MLS primitive
  conformance and removed the misleading E2E claim. The non-ignored
  `native_agent_mls_coauth_soland_restart_replacement_live_e2e` now drives an
  independently managed Garth runtime through a real Coauth/Postgres/Soland
  stack: Agent session issue, KeyPackage upload/claim, standard device-message
  Welcome, persist-before-consume, restart, bidirectional encryption, next
  epoch, and replacement/revoke. Browser human-member E2E and server unit tests
  remain layered evidence rather than substitutes for this path.

## 2026-07-23 Native Agent MLS cross-service live contract gaps

- Severity: P0
- Status: resolved and covered by the live Agent runtime leg.
- Evidence: the first real Coauth/Soland run exposed four contracts that local
  unit tests could not compose: Agent grants omitted the KeyPackage revoke
  action; introspection tried to parse JWT-internal Agent constraints as the
  strict wire `SessionGrantScopeDetails` and omitted Agent freshness; Soland
  required Realm/Strand selectors even for account-scoped KeyPackage and
  device-message actions; and standard device-message delivery recognized only
  ordinary `DeviceIdentity` rows, not an independently paired Agent endpoint.
- Regression class: cross-service authorization tests must use the actual
  introspection wire shape and a freshly built server pair. Runtime endpoint
  eligibility must be derived from the current accepted Agent authorization,
  not merely from the presence of an old KeyPackage or an implementation-local
  device record. Replacement tests must include revoke in the exact issued
  Agent scope.
- Resolution: Coauth now includes revoke, projects only the four wire scope
  fields while rejecting non-object input, and reports Agent Fresh/Stale state.
  Soland requires resource selectors only for resource operations and accepts
  an Agent device-message endpoint only when a live KeyPackage references the
  current accepted `agent_key_authorize_event_id`. The live test additionally
  rejects no-KeyPackage claims, bad upload signatures, wrong session devices,
  Welcome recipient drift, and the superseded session after replacement.

## 2026-07-23 Agent MLS durable replay and pool accounting boundary

- Severity: P0
- Status: resolved in Garth and covered by runtime tests plus the live leg.
- Evidence: the initial lifecycle state machine could return an already-pending
  consume solely by `claim_id`, without proving that the replay carried the
  same message, KeyPackage, and Welcome digest. Its low-watermark count also
  treated consumed packages as usable and could re-emit an expired local
  package in a later upload attempt.
- Regression class: durable protocol retries must compare the immutable
  persisted intent, not only an idempotency identifier. Pool availability must
  count only unexpired `published` records; claimed, consumed, expired, and
  revoked records are never upload or refill candidates. Public typed APIs must
  enforce cross-field invariants even when callers construct DTOs directly and
  bypass Serde deserialization.
- Resolution: Garth validates the complete claim/top-level/governance binding,
  rejects conflicting pending replays, binds snapshot KeyPackages/groups to the
  current principal and device, excludes non-published or expired records from
  upload/refill, drains pending consume/ack work before replacement, and forbids
  replacement from changing principals. Unit tests exercise direct typed
  binding drift, exact replay, restart, consume, and post-consume refill.

## 2026-07-23 Canonical owner migration omitted the serde helper module

- Severity: P0
- Status: resolved during the final cross-repository rebase gate.
- Evidence: Soland's upstream `refactor(canonical): use canonical owner`
  replaced `arkret_core::canonical::*_canonical_timestamp` with root-level
  `arkret_canonical::*_canonical_timestamp`, but the owner crate exposes these
  functions only through `arkret_canonical::serde_helpers`. A clean Coauth
  rebuild therefore failed while compiling `soland-contracts`, before the live
  Agent MLS test could start.
- Regression class: facade retirement must compile every downstream workspace
  against the commit that removes the facade. Mechanical owner migrations must
  target the owner's actual public module, not infer a root re-export from the
  old facade path.
- Resolution: all Soland timestamp Serde attributes now reference
  `arkret_canonical::serde_helpers`; the clean Coauth/Soland builds and live
  cross-service test are rerun after rebase before push.
