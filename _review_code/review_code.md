# Regression Review

## 2026-07-31 live e2e still assumes membership implies capability

Observed while landing the issuer-authority model (spec `88ef83f2`, cotest
`7f8172ad`). Genesis, the Seal-frontier wait and the creator's own
`authorization_ref` are fixed; what remains is a distinct, older gap.

### Joined members author DataEvents with no grant

- Severity: P1
- Status: open.
- Evidence: `invited_members_exchange_post_join_messages_over_account_subscribe`
  gets `capability_denied` — "no capability at seal_ref covers action
  ak.message.create on derived cell
  ak:cell:ak.component.strand.discussion.timeline.v1:..." — for Bob, who has
  joined the Realm but holds no grant.
- Normative position: `zh/authz/capabilities.md` line 700 is explicit that
  membership derives *read* access only; every write action still needs a
  covering grant, and v1 genesis issues none. Before the authority-root model
  the founding self-grant happened to cover members too, which is why these
  scenarios passed without ever granting anything.
- Harness support landed: `TestActorClient` now remembers the grants it holds
  per Realm and names them in `refs[role=authorized_by]` on its DataEvents, and
  `grant_realm_actions_to_client` issues a grant and records it on the subject
  in one call.
- Remaining fix: each scenario whose non-creator writes calls
  `grant_realm_actions_to_client` after the join, naming the actions it
  exercises. This stays scenario-by-scenario rather than a harness-wide switch:
  which actions a member should hold is exactly what these tests pin down.
  Demonstrated on `account_subscribe_long_poll`, which went 0/4 to 3/4 (the
  remaining failure is an unrelated `ak.invite.cancel` lifecycle precondition).
- Scope: ~30 failures across ~20 live test binaries. The conformance, vector and
  wire suites are unaffected and green.

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
- Status: resolved.
- Evidence: all four `tests/account_subscribe_long_poll.rs` cases fail during
  their Realm bootstrap setup with `invalid_realm_founding_grant`.
- Isolation: rebuilding the sibling Soland executable does not change the
  result; the 149 Cotest library/conformance tests, including the new
  accountability vector, pass.
- Root cause: the harness duplicated an obsolete three-action founding grant
  and omitted the registry-derived Realm-create effects. It also modeled invite
  acceptance as a raw member-state write instead of the canonical
  `ak.invite.accept` Control Move.
- Resolution: bootstrap now consumes the SDK founding-action constant and
  derives Realm/invite effects through the canonical builders; invite flows
  carry the accepted Seal basis and atomic invite/member transitions.
- Verification: `cargo test --workspace --quiet` passed after rebasing the
  closed-contract SDK and Soland changes.

## 2026-07-27 Realm singleton media fixtures used the removed Realm-id subject

- Severity: P1
- Status: resolved in Soland and Cotest.
- Evidence: the live media-token and moderation regressions initially failed
  after canonical writers stored `ak.component.realm.media_service.v1:null`;
  the consumer and server fixtures still queried
  `ak.component.realm.media_service.v1:<realm_id>`.
- Resolution: Realm-singleton reads now use the canonical null-subject CellRef
  plus an independent Realm namespace key. Tests prove two Realms cannot see
  each other's singleton value and that a legacy global null-subject value is
  never used as a cross-Realm fallback. The browser assertion also uses the
  canonical `backend_kind` response field.
- Verification: Soland `devices_webrtc` passed 18/18, the complete Soland
  workspace passed, and joint E2E media-token plus durable-ban targeting passed.

## 2026-07-27 Device pairing mixed directory multibase with challenge-proof key bytes

- Severity: P1
- Status: resolved in Inkson, Soland, and Cotest.
- Evidence: live short-link authorization returned
  `failed_precondition/proof_invalid`; the staged `PublicKey.key` contained a
  `z...` directory multibase value while the SDK challenge verifier requires
  the raw 32-byte Ed25519 key encoded as unpadded base64url.
- Resolution: Inkson now emits raw base64url for device-pairing wire objects
  while retaining multibase for directory records. Soland rejects multibase at
  the unauthenticated stage boundary, normalizes an accepted raw key to
  multibase only when persisting the authorized device, and has regressions for
  both boundaries. Cotest signs the server and to-device transcripts with the
  same raw-key representation.
- Verification: Inkson's signer encoding regression passed; Soland's stage and
  storage-normalization regressions passed; joint E2E run `20260727-085210`
  completed the server-mediated short-link flow; Inkson's browser pairing
  feature test passed 1/1.

## 2026-07-27 Joint-full tail failures mixed transport exhaustion with stale harness assumptions

- Severity: P1 for session-grant availability and MLS admission ordering; P2
  for stale response/UI assumptions and scenario budgets.
- Status: resolved in code; intentionally not re-verified after the user's
  stop-testing instruction.
- Evidence: joint-full run `20260727-090720` finished 328 passed / 18 failed /
  101 skipped / 35 not run. Service logs contain 76 occurrences of the
  `auth_unavailable` session-grant introspection failure while the managed
  service monitor recorded zero process failures.
- Root causes:
  - force-fresh introspection reused an Auth Server keep-alive connection after
    the peer had closed it and treated the first transport error as final;
  - several tests asserted transient UI text or obsolete HTTP/error shapes
    instead of the durable partial-accept, read-cursor, invite-disclosure, and
    membership contracts;
  - encrypted Kanban wrote content after invite acceptance but before the
    recipient had observed its durable MLS Welcome;
  - long multi-principal stories inherited the single-action 180-second budget,
    while optimistic message rows had no authoritative-history rehydration
    fallback after a missed acknowledgement edge.
- Resolution: Soland now retries one read-only introspection transport failure
  with a freshly validated/pinned client. Cotest retries only the matching
  bootstrap/login failure, waits for durable MLS admission, uses canonical
  invite acceptance and DPoP sessions, asserts partial rejection and opaque
  quarantine semantics, rehydrates stuck optimistic rows, and gives the
  explicitly long workflows bounded scenario-level budgets.
- Verification boundary: no test, typecheck, lint, or full-run command was
  executed after these changes. The remaining acceptance debt is recorded in
  `arkret-work/work/active/2026-07-27-federation-seal-prerequisite-wire-closure-root-cause-report.md`.

## 2026-07-27 Cotest lagged two upstream contract changes and went red at HEAD

- Severity: P1 (whole `agent_provision_e2e` target failed to compile, so the
  Rust suite could not run at all); P2 for the stale RSVP evaluator.
- Status: resolved and verified — `cargo test --test conformance_fixtures`
  reports 88 passed / 0 failed, and `cargo test --no-run` builds every target.
- Evidence:
  - `error[E0308]` x7 in `tests/agent_provision_e2e.rs` after
    `arkret-rust-sdk@d104b989` (*Centralize protocol value types*) moved
    `controller_authorization_ref` to `DidUrl`, `pairing_request_id` to
    `OpaqueLocalId`, and `AgentKeyAuthorizePayload.key_id` /
    `verification_method` to `NonEmptyString` / `DidUrl`.
  - `final_conformance_closure_fixture_suite_matches_reference_semantics`
    failed with `missing string field status` after `arkret-spec@1e972708`
    replaced the RSVP cell value with the whole `entry`.
- Root causes:
  - the local `PairingOutcome` helper trait still exposed `&str` accessors, so
    the test kept handing raw strings to now-typed SDK constructors;
  - `evaluate_duplicate_rsvp_writes` still keyed the value-level no-op on
    `status` alone, which `calendar-event.md` §8.3 replaced with byte equality
    of the whole `entry`;
  - `assert_expected_subset` treated the fixture's prose `expected.note` as an
    assertable key, although that key is an established fixture convention
    (see also `arkret-private-kdf-fixture.json`).
- Resolution: the helper trait now returns the SDK owner types, the RSVP
  evaluator compares `arkret_canonical::canonical_json_bytes` of the whole
  entry and reports `duplicate_byte_equal_entry_noop`, and the subset assertion
  skips the documentation-only `note` key.
- Prevention dimension: a protocol value-typing change in `arkret-rust-sdk`
  must be followed by `cargo test --no-run` in every downstream repository —
  Cotest's own test targets are consumers of the SDK's public types, and a
  target that no longer compiles hides every assertion it contained.

## 2026-07-27 Push notify outcome assertions still used the removed accepted/rejected buckets

- Severity: P1 (two live scenario targets panicked on `Option::unwrap()`).
- Status: resolved and verified — `cargo test --test delivery_media --test protocol_payloads`
  reports 5 passed / 0 failed.
- Evidence: `src/scenarios/delivery_media.rs` and
  `src/scenarios/protocol_payloads/push.rs` both read `notify["rejected"]`,
  which no longer exists after `arkret-rust-sdk@c2de1c8b` (*close push notify
  outcome contract*) replaced `PushNotifyOutcome` with
  `{push_target_id, outcomes[]}` and a per-device `gateway_status` +
  `reason_code`.
- Resolution: both scenarios now assert the per-device outcome list, including
  the reason-code split soland actually implements — a device that was never
  registered is `push_token_unknown`, while `push_target_unknown` is reserved
  for a registered device whose registration does not accept the requested
  push target.
- Prevention dimension: an outcome DTO that drops a top-level array must be
  greppable across Cotest before the SDK change lands; `value["field"]` reads
  on a removed key degrade to a runtime panic, not a compile error.
## 2026-07-28 — wrong Recovery Key assertion also accepted the success text

- Surface: `e2e/tests/identity/recovery.spec.ts`, B-model all-devices-lost live flow.
- Regression: the negative-key status matcher included `verified`, so the assertion could match
  the success sentence `Recovery Key verified` instead of proving that a valid but unrelated
  mnemonic was rejected.
- Detection: full diff self-review after rebasing the live recovery work onto latest `main`.
- Correction: match only the generic rejection/error states and, before submitting the
  correct key, independently assert that the recovery session has not completed and the fresh
  device is absent from the authoritative active-device projection.
- Prevention dimension: cryptographic negative E2E assertions must verify the absence of durable
  authorization, not only UI text whose vocabulary overlaps the success path.

## 2026-07-28 — legacy account projection fixture has no PCR Seal for later Control Moves

- Severity: P1 for the affected key/device scenarios; unrelated to the push
  outcome migration in this change.
- Status: open. The long-term repair is to replace the fixture bootstrap, not
  weaken Control Move admission or synthesize an ungrounded `seal_basis`.
- Evidence: after rebuilding Soland from current `main`,
  `delivery_media::key_upload_query_and_claim_edges_are_enforced` and
  `protocol_payloads::events_keys_device_blob_push_and_moderation_surfaces_work`
  fail before their key assertions. The shared `register_account` helper calls
  the account projection edge and then tries to publish
  `ak.cross_signing.publish`; the principal control Realm has no accepted Seal,
  while current admission correctly requires `seal_basis.leaves` on that
  Control Move.
- Root cause: the fixture still treats account projection plus dev login as
  identity bootstrap. The P0 transaction protocol separates that projection
  from durable self-PCR creation and finality, so the helper never creates the
  two bootstrap Events or submits their current-device-signed Seal.
- Long-term resolution: make the test principal follow the same SDK path as
  `agent_provision_e2e`: author and submit the self-PCR bootstrap unit, build
  and submit `build_self_principal_bootstrap_seal`, then author cross-signing
  and device authorization against that exact Seal basis. Do not add a
  server-side exemption, accept an empty basis, or retain the projection edge
  as a second identity-creation protocol.
- Verification boundary: the migrated push scenario passes its focused live
  test, Rust workspace check and TypeScript typecheck pass. The two
  identity-dependent scenario targets remain red until the shared fixture is
  migrated.

## 2026-07-30 — Sidecar joint gate could silently skip or inspect the wrong wire shape

- Severity: P1 acceptance-gap risk.
- Status: resolved; the focused real onboarding gate passes and the managed
  joint runner now provisions two independent Savfox gateways.
- Evidence:
  - the live Savfox scenario used `test.skip` whenever external gateway
    variables were absent, while the repository runner had no way to provision
    that prerequisite;
  - the two-user fixture started concurrent principal inception chains even
    though the current local Coauth/Soland identity-binding lease is global,
    producing timeouts unrelated to Sidecar semantics;
  - invite acceptance could navigate to Notifications before the authoritative
    pending-invite projection existed; because Inkson imports that endpoint at
    initial bootstrap, later UI refreshes could not repair the missed fact;
  - the Realm bootstrap listener treated `events[]` entries as bare Events,
    although ingress now carries `EventInitialSubmission` wrappers;
  - an early two-device assertion labeled DOM Event ids as a fold frontier
    instead of reading Inkson's serialized fold projection.
- Resolution: `-StartSavfox` now owns two gateways and deterministic model
  endpoints, required-mode missing prerequisites fail instead of skip,
  principal inception is sequenced, ingress assertions unwrap
  `submission.event`, invite acceptance waits for the authoritative pending
  projection before opening Notifications, and the convergence gate compares
  the real serialized projection and canonical folded frontier from Inkson's
  test-only evidence surface.
- Prevention dimension: a required joint gate must own every external process
  it names, assert canonical wire envelopes rather than historical DTO shapes,
  and distinguish UI echo evidence from protocol fold evidence.

## 2026-08-01 — renamed capability vector was silently undispatched

- Severity: conformance false-positive risk, resolved.
- Regression: the capability fixture was renamed to `authority_chain_multi_level`, but the
  suite dispatcher still matched the removed name. The fixture remained valid JSON and the
  suite passed without executing its authority-chain oracle.
- Correction: dispatch now matches the registered fixture name, typed `issuer_authority_refs`
  drive the oracle, and every new root lifecycle/audit vector has an explicit evaluator arm.
- Prevention dimension: fixture registries should require one-to-one evaluator consumption;
  a known fixture name without a dispatcher must fail instead of falling through to success.

## 2026-08-01 — Agent live fixtures omitted key-backup idempotency

- Severity: live-gate drift; resolved.
- Regression: every `agent_provision_e2e` case uploaded its prerequisite `KeyBackup` with a bare
  PUT. The current operation contract requires `Idempotency-Key`, so Soland correctly rejected all
  six scenarios before Agent pairing with `invalid_param`.
- Correction: both shared backup upload paths now derive a stable request key from the canonical
  `backup_id`. Replaying an identical fixture therefore addresses the same durable operation,
  while different backups cannot collide.
- Prevention dimension: live setup helpers must exercise the same required transport headers as
  product clients; bypassing idempotency at fixture setup hides the exact replay guarantees the
  recovery suite is meant to verify.

## 2026-08-01 — stale live scenarios produced false green or exercised retired wire models

- Severity: conformance false-positive risk; resolved.
- Regression: the third-party invite scenario returned success when create failed, while three
  federation suites fabricated static Seals, placeholder proofs, and direct peer submissions that
  no longer represent the current receiver-relative CBA and proposal-receipt protocol.
- Correction: the skip-as-success 3PID path and obsolete federation suites were deleted. The open
  3PID carrier gap is tracked in `arkret-work/review/spec-open`; canonical Soland peer HTTP coverage
  and the real federation readiness gate remain registered.
- Prevention dimension: required live scenarios may not convert setup failure into success, and a
  protocol migration must delete private fixture protocols once authoritative integration coverage
  exists.

## 2026-08-01 — live fixtures omitted current authorization and CAS inputs

- Severity: live-gate drift; resolved.
- Regression: interaction members relied on membership as write authority, Realm actor-frontier
  Events omitted `seal_ref`/`auth_context`, key-backup PUT omitted `Idempotency-Key`, and account
  data writes omitted `expected_revision`. The recovery-policy negative still posted the retired
  raw policy body instead of `EventInitialSubmission`.
- Correction: fixtures now issue explicit reaction grants, bind DataEvents to the actual Seal and
  authority root, carry stable idempotency/CAS inputs, and delete the obsolete raw-policy test.
- Prevention dimension: fixture builders must consume live frontier/authority state and required
  transport preconditions rather than reconstructing historical request shapes.

## 2026-08-01 — calendar tests raced one shared control coordinator

- Severity: test isolation flake; resolved.
- Regression: only one of three tests in the same binary was serial, so parallel Realm bootstrap
  operations intermittently exhausted the shared coordinator window and timed out before Seal
  publication.
- Correction: all tests in the binary use the same serial isolation contract.
- Prevention dimension: scenarios that share process-global ports, logs, or coordinator state must
  declare isolation consistently at the binary boundary.

## 2026-08-02 — recovery restart gate silently fell back to volatile Soland storage

- Severity: recovery durability false-positive risk; resolved.
- Regression: the ignored four-service recovery test required generic `DATABASE_URL` for Teabay,
  but `FourServiceConfig` reads the independent `COTEST_SOLAND_DATABASE_URL` for Soland. Running
  the documented gate without that second variable booted Soland on its memory store and only
  failed later when the first restart produced a different service identity.
- Correction: the test now requires `COTEST_SOLAND_DATABASE_URL` before bootstrap and passes it
  explicitly into the stack configuration, so the restart gate cannot run against volatile state.
- Verification: the real Coauth/Starid/Teabay/Soland test passed with both server stores backed by
  temporary PostgreSQL; Soland retained its service identity and replayed every durable authority
  ticket, outcome, and terminal receipt across forced restarts.
- Prevention dimension: a durability test must assert its durable backend prerequisite at its own
  entry point; an optional harness default is not an acceptable substitute.
