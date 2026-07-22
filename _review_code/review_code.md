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
