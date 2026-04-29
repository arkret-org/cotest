# cotest Test Strategy

`cotest` is a black-box Contrix server conformance suite. Each scenario starts
the server processes it needs, creates test actors through public APIs, and
asserts only public HTTP behavior plus limited `contrix-rust-sdk` smoke paths.

## Harness Model

- Single-server scenarios start one real server process and verify local
  account, space, repo, sync, media, and policy behavior.
- Multi-server scenarios start two or more real server processes and verify
  federation-facing behavior through public endpoints.
- Shared lifecycle and actor helpers live in `src/harness.rs`.
- Scenario logic lives in `src/scenarios/`; `tests/` stays as thin wrappers so
  the project remains the test harness, not a pile of ad hoc integration files.

## Current Suite Map

### Single-Server

- `service_surface`: health, service description, sync/directory/index describe
  endpoints, and required operation advertisement.
- `api_contracts_auth`: error envelopes, invalid JSON, account register/login,
  logout, and contact edge cases.
- `collaboration_workflow`: account bootstrap, space lifecycle, member add,
  message send, sync, and index projection.
- `delivery_media`: device key upload/query/claim, to-device delivery, blob
  upload/download, range, and hash validation.
- `events_entity_backfill`: event creation, entity projection, timeline reads,
  and missing-event recovery surfaces.
- `identity_directory_index`: identity describe/resolve/document/log/receipt,
  directory search/resolve, export, audit, notifications, and inbox behavior.
- `authz_policy_presence`: grant lifecycle, policy check contract, presence,
  push device registration, and ICE config behavior.
- `interaction_models`: message revision/redaction, reactions, read markers,
  subscriptions, entity CRUD, relations, and view projections.
- `schema_policy_realtime`: schema registry, policy documents, typing
  ephemerals, push rules, and WebRTC signaling sessions.
- `extension_surface_gaps`: executable checks for current applet/agent surface
  gaps so missing routes are tracked by tests instead of ignored placeholders.
- `protocol_payloads`: payload envelope, encrypted content, receipts, and
  protocol object acceptance.
- `repo_sync_index`: repo submit, idempotency, read paths, expanded commit
  reads, repo sync, and parameter edge coverage.
- `space_permissions`: membership, owner-only mutation, deleted-space behavior,
  non-member denial, and private visibility policy checks.

### Multi-Server

- `federation_readiness`: remote service discovery and basic cross-instance
  wiring checks.
- `federation_contract`: transaction/push/pull/verify-actor style contract and
  invalid-input behavior.
- `federation_collaboration`: cross-server membership, remote message
  propagation, sync visibility, and federated projection behavior.

## SDK Usage Policy

- Use `contrix-rust-sdk` for typed protocol objects, commit construction, and
  generic client smoke coverage.
- Prefer raw HTTP assertions for authoritative server-contract checks when the
  current SDK wire model lags the server's live JSON surface.

## Execution

```powershell
$env:COTEST_SUT_MANIFEST = "E:\Works\contrix-dev\soland\Cargo.toml"
cargo test --tests -- --nocapture
```
