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

## 2026-07-24 Coauth request tracing held an entered span across await

- Severity: P0
- Status: resolved in Coauth; targeted joint E2E regressions passed.
- Evidence: the 20260724-191052 joint-full run repeatedly panicked inside
  `tracing-subscriber` with closed-span and missing-span assertions. The
  request tracing middleware kept a `span.enter()` guard alive while awaiting
  the complete Salvo handler chain, allowing the future to move between Tokio
  worker threads while a thread-local span guard remained entered. Affected
  requests surfaced as socket resets, session-grant introspection 503s, and
  account-registration 503s.
- Regression class: async middleware must bind spans with
  `tracing::Instrument` so every future poll enters and exits on the current
  worker. An `Entered` guard must never cross an await point.
- Resolution: the Coauth HTTP tracing middleware now instruments the downstream
  future and records the response fields through the retained span handle.

## 2026-07-24 DND E2E attempted forbidden direct Recovery Key replacement

- Severity: P1
- Status: resolved in Cotest.
- Evidence: the DND cross-device scenario completed canonical account
  bootstrap with a fixture Recovery Key, then navigated to Recovery settings
  and clicked the disabled direct-regeneration control. The joint-full run
  spent its full six-minute timeout waiting for a control intentionally marked
  `Staged handoff required`.
- Normative source: `identity/key-management.md` section 3.3 requires recovery
  secret replacement to use the resumable two-entry handoff and global root
  index. A client must not replace accepted recovery material directly.
- Resolution: the scenario no longer replaces accepted recovery material, and
  the obsolete helper that attempted direct regeneration was removed.
  Follow-up evidence showed that the second login still held only a restricted
  fresh-device session, so the DND enforcement scenario no longer attempts a
  backup unlock before device authorization; that cross-device leg is tracked
  separately as fixme pending the canonical B-model pairing/re-anchor harness.

## 2026-07-24 Joint runner ignored managed-service worker panics

- Severity: P0
- Status: resolved in Cotest.
- Evidence: the 20260724-191052 Coauth stderr contained repeated Tokio worker
  panics, but the run reported `managed_service_failure_count: 0` because the
  runner only classified a whole process/container exit as a managed-service
  failure.
- Regression class: a long-lived service can survive a request-task panic while
  dropping that request and corrupting E2E evidence. A managed-service runtime
  panic must fail the run even when the parent process remains alive.
- Resolution: the runner now scans live process and container logs for Rust
  panic/fatal-runtime markers, records the first signal with file and line
  evidence, forces a nonzero run result, and covers the behavior in its
  self-test.

## 2026-07-24 Encrypted DND writes omitted the account-secret backup trigger

- Severity: P1
- Status: resolved in Inkson; targeted DND regression passed.
- Evidence: device A successfully stored an encrypted `ak.dnd_schedule`, but
  device B logged `ignoring undecryptable ak.dnd_schedule: account secret is
  unavailable` and silently rendered default notification settings. The DND
  write created the account secret but, unlike encrypted Realm, chat, Kanban,
  and file-transfer writes, never invoked the shared first-write backup path.
- Normative source: `identity/key-management.md` section 7.10 says clients
  should automatically and continuously maintain a `secret_storage` backup
  when the account secret or encrypted private account data is created or
  rotated. `artifacts/registry/account-data-key-registry.json` classifies
  `ak.dnd_schedule` as encrypted principal-private account data.
- Resolution: after Soland accepts the encrypted DND value, Inkson now waits
  for the shared recovery-public-key account-secret backup path before
  reporting the settings save complete. The live DND test verifies encrypted
  storage plus suppression/resumption on the authorized device. Fresh-device
  restore remains separate until the device first completes the authorization
  required by `key-management.md` sections 5.1 and 7.3.

## 2026-07-24 DND E2E tried to unlock backup before device authorization

- Severity: P1
- Status: resolved in Cotest; canonical B-model multi-device harness remains
  explicitly fixme.
- Evidence: the same-account second login received a restricted fresh-device
  session grant but never completed pairing or recovery re-anchor. Inkson
  correctly suppressed downstream MLS unlock while
  `needs_device_authorization` remained true, so the test waited 90 seconds for
  an unlock prompt that must not be available in that state.
- Normative source: `identity/key-management.md` section 5.1 forbids a fresh
  device from reading E2EE history or unlocking key backup before SAS/QR
  verification; section 7.3 authorizes the new device before it restores E2EE
  state. A login factor alone is not device authorization.
- Resolution: DND enforcement and encrypted-at-rest assertions now run on the
  already-authorized device. The distinct fresh-device restore assertion is a
  separate fixme with the exact blocker: the harness must bind the accepted
  actor frontier and the new device's real signing key through pairing or the
  B-model recovery re-anchor flow.

## 2026-07-24 Inkson bootstrap continued with a stale session after terminal auth loss

- Severity: P0
- Status: resolved in Inkson; targeted live regression passed.
- Evidence: after hard logout, Inkson rendered the login panel but then issued
  two more authenticated requests with the revoked grant:
  `/_arkret/self/account/viewer` and
  `/_arkret/self/account/subscribe?catchup=true`. The failing Playwright
  assertion consistently observed the authenticated request count grow from
  10 to 12. The trace showed both requests began after terminal 401 responses,
  so this was not an in-flight-request allowance or a brittle exact-count
  assertion.
- Normative source: `identity/account-lifecycle.md` section 4.1 requires the
  client to stop sync and clear local session credentials during hard logout.
- Regression class: the bootstrap task retained an authenticated transport
  across awaits but was not fenced by the app-wide session generation. A
  concurrent terminal denial could invalidate the session while that task
  continued into its next authenticated bootstrap request.
- Resolution: every authenticated bootstrap request and retry now checks the
  `SessionCoordinator` generation before dispatch and after completion. A
  terminal invalidation makes the stale bootstrap task return immediately
  before it can reuse the revoked grant.

## 2026-07-24 Realm creation relied on an opportunistic authenticated transport cache

- Severity: P1
- Status: resolved in Inkson; targeted joint E2E regression passed.
- Evidence: the 20260724-224454 joint-full run rendered
  `authenticated session transport is not initialized; use an async
  provider-aware API path` in the Realm bootstrap wizard. The click handler
  already ran in an async task but called the synchronous cached-transport
  constructor, so a valid session could fail Realm creation when the cache had
  not yet been initialized.
- Normative source: `identity/account-lifecycle.md` section 4.1 requires
  authenticated client work to follow the active session lifecycle. A valid
  session operation must obtain its current authenticated transport through
  the session provider rather than depend on an optional stale cache.
- Resolution: the Realm bootstrap task now awaits the provider-aware
  authenticated transport constructor, which initializes or refreshes the
  shared SDK client before submitting the canonical Realm bootstrap.
- Verification: joint-full targeted run `20260724-235218` passed
  `alice adds a strand description` (1/1).

## 2026-07-24 Kanban overdue UI regression bypassed the authenticated client path

- Severity: P1
- Status: resolved in cotest; targeted joint E2E regression passed.
- Evidence: the `due_date past today renders as overdue badge` browser test
  was another `issueDevSession` + `sessionCredential` caller and failed Realm
  creation in `20260724-224454` with the same missing authenticated transport.
  It also created the board and cards through bare-bearer API helpers, so it did
  not exercise the user flow whose rendering it claimed to cover.
- Normative source: `crypto-media/device-lifecycle.md` section 3.3 requires
  `ak.session.grant` plus DPoP on protected client requests.
- Resolution: the regression now logs in through the Coauth DPoP fixture and
  creates the Realm, board, column, cards, and due date entirely through Inkson
  before asserting the overdue presentation.
- Verification: joint-full targeted run `20260725-000119` passed
  `due_date past today renders as overdue badge` (1/1).

## 2026-07-25 Cross-device notification test raced read-cursor submission

- Severity: P1
- Status: resolved in cotest; targeted joint E2E regression pending.
- Evidence: both `20260724-224454` and the 2-worker failed-subset rerun reached
  the device-2 optimistic `mark-unread-button`, then reloaded device 1 before
  the spawned read-cursor submission completed. Device 1 correctly still
  rendered `Mark read` because no synced actor-private cursor covered the
  notification yet.
- Normative source: `discovery/read-receipts.md` sections 6.5-6.6 define
  cross-device state as convergence from the actor-private
  `ak.read_cursor.advance`, not from another device's local optimistic state.
- Resolution: the test now waits for Inkson's `notifications-status` to report
  that the read cursor was synced before reloading and asserting device-1
  convergence.

## 2026-07-25 Consent settings browser regression used a bare development bearer

- Severity: P1
- Status: resolved in cotest; targeted joint E2E regression pending.
- Evidence: the 2-worker failed-subset trace showed Inkson stopped with
  `no session grant is available for the active principal server`; the test
  opened the settings UI with `issueDevSession` + `sessionCredential`.
- Normative source: `crypto-media/device-lifecycle.md` section 3.3 requires a
  DPoP-bound `ak.session.grant` for protected client requests.
- Resolution: the consent settings browser now uses the Coauth DPoP login
  fixture. Development sessions remain scoped to API fixture setup and
  projection assertions only.

## 2026-07-25 Device-key lifecycle regression parsed an obsolete inline pairing payload

- Severity: P1
- Status: resolved in cotest; targeted joint E2E regression pending.
- Evidence: the failed-subset run raised `Unexpected token 'h'` while parsing
  the `pair-device-secret` value as JSON; Inkson now renders the
  server-mediated `http://.../device-pairing/resolve#token=...` short link.
- Normative source: `crypto-media/device-lifecycle.md` section 2.1.1 requires
  the compact token in the URL fragment and resolves it through the body-only
  open endpoint. The resolved canonical `PublicKey` uses `key`, not the
  obsolete `public_key` field.
- Resolution: the test now verifies that the link has no query, extracts the
  fragment token, resolves it through the open endpoint, and compares
  `new_device_pubkey.key` with the durable device event signer while asserting
  that `public_key` is absent.

## 2026-07-25 Contacts sidebar ignored Agent runtime-key readiness

- Severity: P1
- Status: resolved in Inkson; targeted joint E2E regression pending.
- Evidence: the failed-subset run rendered a freshly provisioned Agent whose
  controller lifecycle was `active` but whose orthogonal runtime state was
  `pending_runtime_key`. `active_agents_only` filtered only the lifecycle axis.
- Normative source: `identity/contact-and-direct-conversation.md` sections 3
  and 6 require a lifecycle-active accountable Agent with effective runtime-key
  facts for a usable direct conversation.
- Resolution: the Contacts chat sidebar now requires lifecycle `Active` and
  runtime state `Ready` or `Replacing`; replacement retains its previous active
  authorization, while bootstrap-pending and expired Agents remain settings-only.

## 2026-07-25 Joint E2E default worker count exceeded shared auth-stack capacity

- Severity: P1
- Status: resolved in cotest; failed-subset verification in progress.
- Evidence: the original joint-full run used four file workers and failed 24
  tests. Three representative failures passed alone. A four-worker rerun of
  the failure titles rapidly reproduced broad login/invite cascades, whereas
  the same precise subset with two workers passed the early capability,
  policy-server, and media-token cases and reduced the remaining failures to
  six independently diagnosable regressions.
- Normative source: this is harness capacity rather than protocol semantics;
  the test runner must preserve the spec-defined fail-closed behavior without
  creating artificial authentication starvation.
- Resolution: Playwright now defaults to two file workers. Individual tests
  may still create multiple sessions concurrently, and explicitly provisioned
  environments can override the count through `COTEST_PW_WORKERS`.

## 2026-07-25 Kanban week workflow waited on a replaced Add Card button

- Severity: P2
- Status: resolved in cotest; targeted joint E2E regression pending.
- Evidence: the 2-worker trace showed the second Add Card click had already
  opened the editor, but Playwright kept waiting because Dioxus replaced the
  clicked button during re-render, eventually exhausting the test timeout.
- Normative source: no protocol behavior changed; the test must observe the
  resulting editor state rather than require a stale DOM node's click promise
  to settle.
- Resolution: the workflow now uses the established Kanban helper pattern:
  a short bounded click whose replacement is accepted only when the title
  editor is visibly open, followed by explicit input and save readiness checks.

## 2026-07-24 Encrypted Kanban browser regressions used a bare development bearer

- Severity: P1
- Status: resolved in cotest; targeted joint E2E regression passed.
- Evidence: the targeted Realm-description trace reported that
  `inkson.test.session_injection.v1` was absent and only the legacy
  `session_credential` fixture was present. The three creator-device encrypted
  Kanban regressions called `issueDevSession` and opened Inkson with a bare
  development bearer, so the provider correctly had no DPoP-bound session
  grant to restore.
- Normative source: `crypto-media/device-lifecycle.md` section 3.3 requires
  `ak.session.grant` plus DPoP for `/_arkret/self/*`; a bearer is only the grant
  carrier and cannot authenticate a protected endpoint by itself.
- Resolution: all three encrypted creator-device Kanban regressions now use
  the existing Coauth-minted DPoP session fixture, including the bound grant
  key and separate event-signing key.
- Verification: joint-full targeted run `20260724-235218` passed
  `alice adds a strand description` (1/1).
## 2026-07-25 Native Agent evidence validator expected an obsolete OR-set shape

- Severity: P1
- Status: resolved in the SDK; real Savfox joint E2E passed.
- Evidence: Soland produced a state-root-backed Agent authorization witness
  using the registry-defined OR-set dot `{ "tag": authorize_event_id,
  "value": authorization_record }`, while the SDK searched for the obsolete
  `accepted_event_id` field and downgraded a valid Agent message to
  `needs_verification`.
- Normative source: the reducer profile registry defines
  `ak.component.agent.key.v1` as an OR-set whose authorization Event id is the
  dot tag; portable evidence must verify that exact canonical state.
- Resolution: the validator now matches the canonical tag/value record and
  rejects legacy or partially matching shapes. Unit fixtures and the live
  Savfox `pong` workflow cover the regression.

## 2026-07-25 Trusted local service WebVH resolution was blocked by actor-DID SSRF policy

- Severity: P1
- Status: resolved in Inkson and the SDK; real Savfox joint E2E passed.
- Evidence: Inkson correctly rejected loopback `did:webvh` hosts in its generic
  untrusted actor resolver, but applied the same policy to the configured
  Principal Server's own source-service DID. The freshness signature key was
  therefore unresolved even though `describe.service_id` matched the service.
- Normative source: Agent evidence requires independent source-signature and
  WebVH-chain verification; a configured same-origin service is a distinct
  trust boundary from an arbitrary actor-controlled DID URL.
- Resolution: the generic resolver remains fail-closed. A narrowly scoped
  fallback first proves exact `describe.service_id`, scheme/host/explicit-port
  origin equality, then fetches only that DID's `did.json` and `did.jsonl` with
  content and size bounds and verifies the complete WebVH chain plus exact
  current-document equality through the SDK pure verifier.

## 2026-07-27 Realm founding grant rejected by live HTTP tests

- Severity: P1
- Status: open; independent of the accountability scope-set subject change.
- Evidence: all four `tests/account_subscribe_long_poll.rs` cases fail during
  their Realm bootstrap setup with `invalid_realm_founding_grant`.
- Isolation: rebuilding the sibling Soland executable does not change the
  result; the 149 Cotest library/conformance tests, including the new
  accountability vector, pass.
- Follow-up dimension: audit the Realm bootstrap Event-to-Operation projection
  and founding capability reducer independently of accountability addressing.
