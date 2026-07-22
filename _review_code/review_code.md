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
  `20260723-023445` (`2 passed (3.7m)`, managed service failures `[]`).
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
