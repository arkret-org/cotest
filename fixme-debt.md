# fixme debt

Generated: 2026-05-22T13:20:46.927Z

| metric | count |
|---|---:|
| total fixme | 224 |
| missing metadata | 0 |
| expired expected_live_by | 0 |

## soland#authz-policy-server-check-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/authz/policy-server-check.spec.ts:118 | alice configures policy server; invite triggers /policy/check with allow→deny→obligation lifecycle | e2e/scenarios/authz/policy-server-check.md | - |
| 2026Q3 | tracked | e2e/tests/authz/policy-server-check.spec.ts:227 | E3.1 policy server timeout → soland fail-closed (deny with reason policy_timeout) | e2e/scenarios/authz/policy-server-check.md | - |
| 2026Q3 | tracked | e2e/tests/authz/policy-server-check.spec.ts:275 | E3.2 multi-source priority: org policy_server overrides realm policy_server (more-specific wins) | e2e/scenarios/authz/policy-server-check.md | - |
| 2026Q3 | tracked | e2e/tests/authz/policy-server-check.spec.ts:332 | E3.3 cache_ttl idempotency: repeated identical action within ttl triggers only one upstream /policy/check | e2e/scenarios/authz/policy-server-check.md | - |

## soland#calls-webrtc-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/calls/webrtc.spec.ts:103 | E18.F mid-call TURN credential refresh: long calls renew credentials before expiry; call does not drop | e2e/scenarios/calls/webrtc.md | - |
| 2026Q3 | tracked | e2e/tests/calls/webrtc.spec.ts:113 | E18.7 pairwise pseudonym in TURN credentials: username does not contain alice.did plaintext (spec §6 pseudonymization) | e2e/scenarios/calls/webrtc.md | - |
| 2026Q3 | tracked | e2e/tests/calls/webrtc.spec.ts:41 | alice initiates 1:1 call to bob; Call Morph state transitions ringing → connecting → active via cx.call.signal frames | e2e/scenarios/calls/webrtc.md | - |
| 2026Q3 | tracked | e2e/tests/calls/webrtc.spec.ts:53 | alice mutes mic: cx.call.signal{kind=mute_state, muted=true} routes to bob; bob's UI shows muted indicator | e2e/scenarios/calls/webrtc.md | - |
| 2026Q3 | tracked | e2e/tests/calls/webrtc.spec.ts:63 | alice shares screen: getDisplayMedia track added; cx.call.signal{kind=media_state, screen_share=true} routes | e2e/scenarios/calls/webrtc.md | - |
| 2026Q3 | tracked | e2e/tests/calls/webrtc.spec.ts:73 | hangup terminates peer connections; Call Morph state=ended; duration persisted | e2e/scenarios/calls/webrtc.md | - |
| 2026Q3 | tracked | e2e/tests/calls/webrtc.spec.ts:83 | group call mode=sfu: alice+bob+carol join; recording_policy=allow lets carol start recording (writes recording_blob_ref) | e2e/scenarios/calls/webrtc.md | - |
| 2026Q3 | tracked | e2e/tests/calls/webrtc.spec.ts:93 | E18.E recording_policy=none rejects carol's recording attempt with failed_precondition reason=recording_policy_violation | e2e/scenarios/calls/webrtc.md | - |

## soland#conformance-encoding-vectors-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/conformance/encoding-vectors.spec.ts:605 | §3.4 hard erasure receipt + §3.5 snapshot pruning verification stub | e2e/scenarios/conformance/encoding-vectors.md | - |

## soland#conformance-profile-gates-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/conformance/profile-gates.spec.ts:225 | Phase B — unsupported standard event kind submit MUST fail closed (no silent accept-and-drop) | e2e/scenarios/conformance/profile-gates.md | - |
| 2026Q3 | tracked | e2e/tests/conformance/profile-gates.spec.ts:259 | Phase C — event requiring an undeclared critical extension MUST fail closed | e2e/scenarios/conformance/profile-gates.md | - |
| 2026Q3 | tracked | e2e/tests/conformance/profile-gates.spec.ts:293 | Phase A coauth — coauth self-claims auth_server only, not identity_registry/principal_server | e2e/scenarios/conformance/profile-gates.md | - |

## soland#conformance-registry-drift-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/conformance/registry-drift.spec.ts:292 | Phase A — POST event with removed kind is hard-rejected with schema_violation | e2e/scenarios/conformance/registry-drift.md | - |
| 2026Q3 | tracked | e2e/tests/conformance/registry-drift.spec.ts:321 | Phase B — calling a removed operation_id returns 410 / 4xx, never 2xx | e2e/scenarios/conformance/registry-drift.md | - |
| 2026Q3 | tracked | e2e/tests/conformance/registry-drift.spec.ts:347 | Phase F — server-managed audit / log surfaces don't leak forbidden model terms | e2e/scenarios/conformance/registry-drift.md | - |

## soland#conformance-snapshot-query-scalability-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/conformance/snapshot-query-scalability.spec.ts:100 | Phase B — snapshot signature binding verifies against recorded signer DID | e2e/scenarios/conformance/snapshot-query-scalability.md | - |
| 2026Q3 | tracked | e2e/tests/conformance/snapshot-query-scalability.spec.ts:125 | Phase C — query filters / sort / pagination return expected_rows in order | e2e/scenarios/conformance/snapshot-query-scalability.md | - |
| 2026Q3 | tracked | e2e/tests/conformance/snapshot-query-scalability.spec.ts:149 | Phase D — query schema fail-closed on unknown ops / conflicting sort / unauthorized fields | e2e/scenarios/conformance/snapshot-query-scalability.md | - |
| 2026Q3 | tracked | e2e/tests/conformance/snapshot-query-scalability.spec.ts:174 | Phase E — scalability constraints fail-closed (page_size / batch / depth / envelope) | e2e/scenarios/conformance/snapshot-query-scalability.md | - |
| 2026Q3 | tracked | e2e/tests/conformance/snapshot-query-scalability.spec.ts:80 | Phase A — snapshot manifest integrity (digest, chunk count, chunk hashes) | e2e/scenarios/conformance/snapshot-query-scalability.md | - |

## soland#discovery-directory-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/discovery/directory.spec.ts:138 | presence: bob closes tab → alice's directory shows presence-offline; bob reopens → presence-online within 5s | e2e/scenarios/discovery/directory.md | - |

## soland#discovery-notifications-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/discovery/notifications.spec.ts:119 | Do-not-disturb window suppresses all notifications during configured hours; resumes after window ends | e2e/scenarios/discovery/notifications.md | - |
| 2026Q3 | tracked | e2e/tests/discovery/notifications.spec.ts:233 | E2EE space with evaluation_locus=client: server sends blind wake; client decrypts and evaluates 'contains_keyword' rule locally | e2e/scenarios/discovery/notifications.md | - |
| 2026Q3 | tracked | e2e/tests/discovery/notifications.spec.ts:243 | cross-device read state: marking read on device-2 clears unread on device-1 within sync window | e2e/scenarios/discovery/notifications.md | - |
| 2026Q3 | tracked | e2e/tests/discovery/notifications.spec.ts:57 | muting a space stops push notifications for new messages but mention still notifies (spec §3 mention override) | e2e/scenarios/discovery/notifications.md | - |

## soland#documents-collaboration-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/documents/collaboration.spec.ts:102 | E17.2 comment anchored to a range that was later removed becomes orphaned (state=locked); UI surfaces orphan badge | e2e/scenarios/documents/collaboration.md | - |
| 2026Q3 | tracked | e2e/tests/documents/collaboration.spec.ts:40 | alice creates a Document Morph (morph_type=document); bob joins same space and sees initial body | e2e/scenarios/documents/collaboration.md | - |
| 2026Q3 | tracked | e2e/tests/documents/collaboration.spec.ts:52 | alice and bob edit concurrently; both edits visible after lattice merge (mv-register or cas-register depending on lattice) | e2e/scenarios/documents/collaboration.md | - |
| 2026Q3 | tracked | e2e/tests/documents/collaboration.spec.ts:62 | alice's cursor position propagates to bob's view via cx.presence ephemeral signal within 1s | e2e/scenarios/documents/collaboration.md | - |
| 2026Q3 | tracked | e2e/tests/documents/collaboration.spec.ts:72 | bob anchors a comment to text range offset 100..110; alice's view shows the comment marker at that range | e2e/scenarios/documents/collaboration.md | - |
| 2026Q3 | tracked | e2e/tests/documents/collaboration.spec.ts:82 | document versions: each anchor finality boundary produces a labeled version; /document/:id/versions lists them | e2e/scenarios/documents/collaboration.md | - |
| 2026Q3 | tracked | e2e/tests/documents/collaboration.spec.ts:92 | restore an earlier version: cx.morph.update with state_witness + inclusion_proof referring to past anchor accepted; current state reverts | e2e/scenarios/documents/collaboration.md | - |

## soland#encryption-audited-e2ee-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/encryption/audited-e2ee.spec.ts:30 | alice configures audit_disclosure_policy on E2EE space; cx.moderation.frank generated for each encrypted message (ciphertext_digest only, no plaintext) | e2e/scenarios/encryption/audited-e2ee.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/audited-e2ee.spec.ts:40 | report on a message triggers audit_disclosure_policy.trigger; audit-agent is invited to access via attested ceremony | e2e/scenarios/encryption/audited-e2ee.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/audited-e2ee.spec.ts:51 | audit-agent's access writes cx.audit.accessed entry; alice in space-admin/audit sees the access record | e2e/scenarios/encryption/audited-e2ee.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/audited-e2ee.spec.ts:61 | E25.1 tampered cx.moderation.frank ciphertext_digest causes downstream verification to fail | e2e/scenarios/encryption/audited-e2ee.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/audited-e2ee.spec.ts:69 | E25.3 alice revokes audit_disclosure_policy; subsequent audit-agent requests are rejected (still leaving historical accessed records intact) | e2e/scenarios/encryption/audited-e2ee.md | - |

## soland#encryption-encrypted-attachments-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/encryption/encrypted-attachments.spec.ts:44 | alice uploads XChaCha20-encrypted attachment; metadata media_type is application/octet-stream (no plaintext leak) | e2e/scenarios/encryption/encrypted-attachments.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/encrypted-attachments.spec.ts:54 | bob (member) downloads blob; client verifies sha256(ciphertext) === ciphertext_digest before decrypt | e2e/scenarios/encryption/encrypted-attachments.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/encrypted-attachments.spec.ts:64 | mallory (non-member) GET on the same blob_ref returns opaque 403/404 indistinguishable from non-existent | e2e/scenarios/encryption/encrypted-attachments.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/encrypted-attachments.spec.ts:74 | blob service stores only ciphertext + blob_ref + size; no plaintext filename or media type in service logs | e2e/scenarios/encryption/encrypted-attachments.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/encrypted-attachments.spec.ts:84 | E12.2 thumbnail generation: client encrypts thumbnail and uploads as separate blob; server cannot derive thumbnails in E2EE | e2e/scenarios/encryption/encrypted-attachments.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/encrypted-attachments.spec.ts:94 | E12.4 audited E2EE: cx.moderation.frank receipt visible to audit agent without revealing plaintext | e2e/scenarios/encryption/encrypted-attachments.md | - |

## soland#encryption-key-backup-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/encryption/key-backup.spec.ts:104 | E13.4 mixed_secret_storage=true is allowed in personal_node profile but rejected in high_assurance | e2e/scenarios/encryption/key-backup.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/key-backup.spec.ts:114 | E13.7 DELETE backup requires ownership proof (SSK signature); session-token-only DELETE rejected | e2e/scenarios/encryption/key-backup.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/key-backup.spec.ts:49 | alice sets up passphrase-protected backup via /settings/recovery; Argon2id KDF + XChaCha20-Poly1305 envelope uploaded | e2e/scenarios/encryption/key-backup.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/key-backup.spec.ts:61 | device-2 restores from backup with correct passphrase; commitment match → ciphertext decrypted locally; no server oracle | e2e/scenarios/encryption/key-backup.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/key-backup.spec.ts:73 | device-2 replays cx.mls.commit chain using backup's mls_history_backup_key; pre-loss E2EE messages decrypt | e2e/scenarios/encryption/key-backup.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/key-backup.spec.ts:84 | E13.1 wrong passphrase: client rejects at key_commitment stage; no GET issued to server (avoids oracle) | e2e/scenarios/encryption/key-backup.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/key-backup.spec.ts:94 | E13.2 tampered ciphertext: digest mismatch → client refuses to decrypt | e2e/scenarios/encryption/key-backup.md | - |

## soland#encryption-mls-group-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/encryption/mls-group.spec.ts:213 | alice and bob exchange E2EE messages; client decrypts plaintext, raw event payload is ciphertext only (no plaintext leak) | e2e/scenarios/encryption/mls-group.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/mls-group.spec.ts:224 | carol added in epoch 1 → cx.mls.commit advances to epoch 2; carol cannot decrypt pre-join messages (history_visibility=joined) | e2e/scenarios/encryption/mls-group.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/mls-group.spec.ts:234 | alice bans bob → membership_frontier advances; client enters epoch_update_required state for up to max_mls_commit_delay_ms | e2e/scenarios/encryption/mls-group.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/mls-group.spec.ts:244 | E11.1 concurrent MLS commits produce ⊥ in covered_frontier_cell; subsequent messages marked decryption_pending until later commit resolves | e2e/scenarios/encryption/mls-group.md | - |
| 2026Q3 | tracked | e2e/tests/encryption/mls-group.spec.ts:254 | E11.2 governance_binding.space_policy_hash mismatch causes federation push to reject with governance_binding_mismatch | e2e/scenarios/encryption/mls-group.md | - |

## soland#extensions-agent-protocol-interop-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/extensions/agent-protocol-interop.spec.ts:141 | Phase B — capability approval with allowed_endpoints / requires_human_approval gate | e2e/scenarios/extensions/agent-protocol-interop.md | - |
| 2026Q3 | tracked | e2e/tests/extensions/agent-protocol-interop.spec.ts:184 | Phase C — invocation handoff with throttled status transcript | e2e/scenarios/extensions/agent-protocol-interop.md | - |
| 2026Q3 | tracked | e2e/tests/extensions/agent-protocol-interop.spec.ts:228 | Phase D — publish-to-source flow lands Flow + Morph with attribution | e2e/scenarios/extensions/agent-protocol-interop.md | - |
| 2026Q3 | tracked | e2e/tests/extensions/agent-protocol-interop.spec.ts:279 | Phase E — audit chain start → status* → result is contiguous and verifiable | e2e/scenarios/extensions/agent-protocol-interop.md | - |
| 2026Q3 | tracked | e2e/tests/extensions/agent-protocol-interop.spec.ts:97 | Phase A — agent endpoint discovery via cx.agent.endpoint + DID Document service binding | e2e/scenarios/extensions/agent-protocol-interop.md | - |

## soland#extensions-applet-bridge-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/extensions/applet-bridge.spec.ts:149 | E4.1 namespace conflict: second applet claiming same namespace is rejected with 409 applet_namespace_conflict | e2e/scenarios/extensions/applet-bridge.md | - |
| 2026Q3 | tracked | e2e/tests/extensions/applet-bridge.spec.ts:164 | E4.2 capability revoke: after applet revoke, bot_actor's own message writes are also rejected (not just ghost path) | e2e/scenarios/extensions/applet-bridge.md | - |
| 2026Q3 | tracked | e2e/tests/extensions/applet-bridge.spec.ts:180 | E4.3 idempotency: re-registering same manifest_id with same Idempotency-Key returns the original {applet_id, bot_actor_did}; different key + same manifest_id is 409 applet_already_registered | e2e/scenarios/extensions/applet-bridge.md | - |
| 2026Q3 | tracked | e2e/tests/extensions/applet-bridge.spec.ts:29 | applet registers, bot joins space, ghost actor relays external messages with accountability chain | e2e/scenarios/extensions/applet-bridge.md | - |

## soland#extensions-mimi-federation-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/extensions/mimi-federation.spec.ts:22 | alice opens MIMI-enabled Realm; bob_mimi joins via facade; bidirectional messaging with identity bridging | e2e/scenarios/extensions/mimi-federation.md | - |
| 2026Q3 | tracked | e2e/tests/extensions/mimi-federation.spec.ts:56 | E5.1 MIMI endpoint 不可达 → federation fallback: 消息本地保留 + outbound 状态标记 deferred,facade 恢复后重试 | e2e/scenarios/extensions/mimi-federation.md | - |
| 2026Q3 | tracked | e2e/tests/extensions/mimi-federation.spec.ts:69 | E5.2 E2EE 在 MIMI 中的转换:transcript binding 或 explicit downgrade 标记,绝不静默泄露明文 | e2e/scenarios/extensions/mimi-federation.md | - |
| 2026Q3 | tracked | e2e/tests/extensions/mimi-federation.spec.ts:83 | E5.3 content type 差异:MIMI 特有 content kind → quarantine + cx.morph.unknown_content_kind | e2e/scenarios/extensions/mimi-federation.md | - |

## soland#federation-cross-server-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/federation/cross-server.spec.ts:221 | α invite UI event automatically fans out to β and β acceptance propagates back to α | e2e/scenarios/federation/cross-server.md | - |
| 2026Q3 | tracked | e2e/tests/federation/cross-server.spec.ts:235 | two-way timeline messaging: alice@α and bob@β exchange messages and both servers converge on identical effective state | e2e/scenarios/federation/cross-server.md | - |
| 2026Q3 | tracked | e2e/tests/federation/cross-server.spec.ts:252 | Pull / backfill: after a network partition, β fetches missing α events via GET /api/v1/federation/pull-operations | e2e/scenarios/federation/cross-server.md | - |
| 2026Q3 | tracked | e2e/tests/federation/cross-server.spec.ts:264 | Idempotent push: replaying the same (origin, destination, event_id) returns accepted (no duplicate write); reducer_profile_hash mismatch returns rejected with reason_code=reducer_profile_mismatch | e2e/scenarios/federation/cross-server.md | - |
| 2026Q3 | tracked | e2e/tests/federation/cross-server.spec.ts:276 | Capability revoke fanout: after alice revokes β's service delegation, α MUST stop pushing future events to β (§4.4) | e2e/scenarios/federation/cross-server.md | - |
| 2026Q3 | tracked | e2e/tests/federation/cross-server.spec.ts:287 | RFC 9421 signature failure: tampered Signature header makes β reject the entire batch with 4xx | e2e/scenarios/federation/cross-server.md | - |

## soland#governance-gdpr-audit-retention-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/governance/gdpr-audit-retention.spec.ts:183 | retention_policy.ttl: events older than the TTL are tombstoned (not physically deleted if anchored) | e2e/scenarios/governance/gdpr-audit-retention.md | - |
| 2026Q3 | tracked | e2e/tests/governance/gdpr-audit-retention.spec.ts:193 | E27.3 cross-server erasure fan-out: alice's DID erased on α; β tombstones her events too within reconciliation window | e2e/scenarios/governance/gdpr-audit-retention.md | - |

## soland#governance-organization-policy-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/governance/organization-policy.spec.ts:28 | acme-org publishes cx.organization.moderation_policy with deny_join targets; spaces under acme inherit the policy automatically | e2e/scenarios/governance/organization-policy.md | - |
| 2026Q3 | tracked | e2e/tests/governance/organization-policy.spec.ts:38 | mallory's join attempt on an Acme space is rejected with organization_policy_denied; space-level override requires organization approval | e2e/scenarios/governance/organization-policy.md | - |
| 2026Q3 | tracked | e2e/tests/governance/organization-policy.spec.ts:46 | policy update at organization level fans out to all member spaces without per-space rewrites | e2e/scenarios/governance/organization-policy.md | - |
| 2026Q3 | tracked | e2e/tests/governance/organization-policy.spec.ts:54 | tab-organizations search returns acme-org with member count and verified badge | e2e/scenarios/governance/organization-policy.md | - |
| 2026Q3 | tracked | e2e/tests/governance/organization-policy.spec.ts:64 | E30.1 cross-org space joining most-restrictive of the two organizations' policies | e2e/scenarios/governance/organization-policy.md | - |
| 2026Q3 | tracked | e2e/tests/governance/organization-policy.spec.ts:72 | appeal flow: mallory submits appeal via policy.appeal.endpoint; moderator reviews; possible override | e2e/scenarios/governance/organization-policy.md | - |

## soland#governance-personal-blocklist-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/governance/personal-blocklist.spec.ts:145 | E11.1 quarantine vs block: server-side quarantine hides a message for everyone; personal block only hides for the blocker — the two operate independently | e2e/scenarios/governance/personal-blocklist.md | - |
| 2026Q3 | tracked | e2e/tests/governance/personal-blocklist.spec.ts:160 | E11.2 mute vs block: muted user's messages still render in timeline but produce no push; blocked user's messages render not at all | e2e/scenarios/governance/personal-blocklist.md | - |
| 2026Q3 | tracked | e2e/tests/governance/personal-blocklist.spec.ts:173 | E11.3 blocked user's view: bob still sees his own messages persisted normally and is never told he was blocked by alice (anti social-graph leak) | e2e/scenarios/governance/personal-blocklist.md | - |
| 2026Q3 | tracked | e2e/tests/governance/personal-blocklist.spec.ts:36 | alice blocks bob; bob's messages filtered from alice's timeline; unblock restores visibility; federation propagates block | e2e/scenarios/governance/personal-blocklist.md | - |

## soland#identity-account-device-auth-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/identity/account-device-auth.spec.ts:32 | alice registers via OIDC bridge (mock IdP); coauth issues short-term cx.session.grant + refresh_token | e2e/scenarios/identity/account-device-auth.md | - |
| 2026Q3 | tracked | e2e/tests/identity/account-device-auth.spec.ts:43 | device-2 pairs via QR + cross-signing; coauth issues device-specific session_grant | e2e/scenarios/identity/account-device-auth.md | - |
| 2026Q3 | tracked | e2e/tests/identity/account-device-auth.spec.ts:53 | expired access token triggers /api/v1/auth/refresh; new session_grant issued without re-OIDC | e2e/scenarios/identity/account-device-auth.md | - |
| 2026Q3 | tracked | e2e/tests/identity/account-device-auth.spec.ts:63 | soft logout revokes access token but keeps refresh; refresh later restores access | e2e/scenarios/identity/account-device-auth.md | - |

## soland#identity-account-states-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/identity/account-states.spec.ts:33 | soft logout revokes access token; refresh token still works to get new access | e2e/scenarios/identity/account-states.md | - |
| 2026Q3 | tracked | e2e/tests/identity/account-states.spec.ts:43 | admin lock: POST /admin/accounts/<did>/lock → all sessions invalidated; /account/me returns 401 | e2e/scenarios/identity/account-states.md | - |
| 2026Q3 | tracked | e2e/tests/identity/account-states.spec.ts:51 | governance suspend: new token requests rejected; old in-flight tokens valid until expiry | e2e/scenarios/identity/account-states.md | - |
| 2026Q3 | tracked | e2e/tests/identity/account-states.spec.ts:61 | user-initiated deactivate: all tokens revoked; account state=deactivated; messages remain visible (deactivated ≠ erasure) | e2e/scenarios/identity/account-states.md | - |
| 2026Q3 | tracked | e2e/tests/identity/account-states.spec.ts:69 | audit: each state transition writes cx.account.state_change with from/to/actor/reason/timestamp | e2e/scenarios/identity/account-states.md | - |
| 2026Q3 | tracked | e2e/tests/identity/account-states.spec.ts:77 | E28.2 cross-server suspension: alice suspended on α; β learns of suspension via sync within reconciliation window | e2e/scenarios/identity/account-states.md | - |

## soland#identity-consent-grant-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/identity/consent-grant.spec.ts:138 | alice grants consent and bob can establish contact (full lifecycle) | e2e/scenarios/identity/consent-grant.md | - |
| 2026Q3 | tracked | e2e/tests/identity/consent-grant.spec.ts:207 | E1.1 time-windowed consent expires after valid_until elapses | e2e/scenarios/identity/consent-grant.md | - |
| 2026Q3 | tracked | e2e/tests/identity/consent-grant.spec.ts:254 | E1.2 revoke then re-grant lifecycle | e2e/scenarios/identity/consent-grant.md | - |
| 2026Q3 | tracked | e2e/tests/identity/consent-grant.spec.ts:309 | E1.3 scope-granularity: invite-scope consent does not allow call | e2e/scenarios/identity/consent-grant.md | - |
| 2026Q3 | tracked | e2e/tests/identity/consent-grant.spec.ts:353 | E1.4 pairwise DID consent isolates contact channels | e2e/scenarios/identity/consent-grant.md | - |

## soland#identity-multi-device-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/identity/multi-device.spec.ts:129 | E10.E to-device message queued for Device 2 before revocation is dropped after revocation (spec §7 line 341 grace drop) | e2e/scenarios/identity/multi-device.md | - |
| 2026Q3 | tracked | e2e/tests/identity/multi-device.spec.ts:57 | Device 1 scans Device 2's QR; signs cx.device.authorized with cross_signing_binding; Device 2 syncs and joins existing MLS groups via Welcome | e2e/scenarios/identity/multi-device.md | - |
| 2026Q3 | tracked | e2e/tests/identity/multi-device.spec.ts:69 | both devices show up in alice's device list via cx.device.list_update projection within 30s of pairing | e2e/scenarios/identity/multi-device.md | - |
| 2026Q3 | tracked | e2e/tests/identity/multi-device.spec.ts:79 | alice messages from Device 1 appear in Device 2's timeline; both have distinct device_id but same actor_id | e2e/scenarios/identity/multi-device.md | - |
| 2026Q3 | tracked | e2e/tests/identity/multi-device.spec.ts:89 | Device 1 revokes Device 2 via cx.device.revoked; Device 2's subsequent /api/v1/events POST returns device_revoked | e2e/scenarios/identity/multi-device.md | - |
| 2026Q3 | tracked | e2e/tests/identity/multi-device.spec.ts:99 | after revoke in an E2EE space, MLS Remove triggers epoch advance; Device 2 cannot decrypt subsequent messages | e2e/scenarios/identity/multi-device.md | - |

## soland#identity-onboarding-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/identity/onboarding.spec.ts:107 | E7.5 handle conflict (\"@alice-s7\" already claimed) rejects with handle_already_claimed | e2e/scenarios/identity/onboarding.md | - |
| 2026Q3 | tracked | e2e/tests/identity/onboarding.spec.ts:41 | alice registers via passkey/WebAuthn; coauth binds principal DID and issues short-term cx.session.grant | e2e/scenarios/identity/onboarding.md | - |
| 2026Q3 | tracked | e2e/tests/identity/onboarding.spec.ts:53 | alice's did:webvh entry 0 is published; SCID derived; DID Document resolves and exposes ContrixPrincipalServer service endpoint | e2e/scenarios/identity/onboarding.md | - |
| 2026Q3 | tracked | e2e/tests/identity/onboarding.spec.ts:64 | principal control space is created (purpose=principal_control); first device registered via cx.device.authorized; cross-signing PSK/SSK/USK published | e2e/scenarios/identity/onboarding.md | - |
| 2026Q3 | tracked | e2e/tests/identity/onboarding.spec.ts:75 | bob registers via OIDC bridge (mock IdP); coauth verifies ID token and binds a fresh DID | e2e/scenarios/identity/onboarding.md | - |
| 2026Q3 | tracked | e2e/tests/identity/onboarding.spec.ts:86 | carol registers via email-only (3PID precursor); verification token consumed; DID issued | e2e/scenarios/identity/onboarding.md | - |
| 2026Q3 | tracked | e2e/tests/identity/onboarding.spec.ts:97 | E7.1 re-registering the same WebAuthn credential is rejected with account_already_registered | e2e/scenarios/identity/onboarding.md | - |

## soland#identity-recovery-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/identity/recovery.spec.ts:31 | alice (device-1) configures passphrase-protected backup; envelope uses Argon2id KDF + XChaCha20-Poly1305; key_commitment uploaded | e2e/scenarios/identity/recovery.md | - |
| 2026Q3 | tracked | e2e/tests/identity/recovery.spec.ts:42 | device-2 restores account using passphrase; SSK/USK recovered; new device authorized via cx.device.authorized with recovery proof | e2e/scenarios/identity/recovery.md | - |
| 2026Q3 | tracked | e2e/tests/identity/recovery.spec.ts:52 | after restore, device-2 syncs E2EE history and decrypts messages sent while device-1 was offline | e2e/scenarios/identity/recovery.md | - |
| 2026Q3 | tracked | e2e/tests/identity/recovery.spec.ts:62 | E8.4 threshold recovery (3-of-5 shares): client reconstructs recovery key from shares; envelope decrypted; device authorized | e2e/scenarios/identity/recovery.md | - |
| 2026Q3 | tracked | e2e/tests/identity/recovery.spec.ts:72 | E8.5 trusted recovery service: third-party signs recovery attestation; client gates backup decrypt on attestation validity | e2e/scenarios/identity/recovery.md | - |
| 2026Q3 | tracked | e2e/tests/identity/recovery.spec.ts:82 | E8.6 mixed_secret_storage=true rejected in high_assurance profile but accepted in personal_node | e2e/scenarios/identity/recovery.md | - |
| 2026Q3 | tracked | e2e/tests/identity/recovery.spec.ts:92 | E8.7 after device-1 revoked, restore still succeeds; historical access honors current membership (not pre-revoke) | e2e/scenarios/identity/recovery.md | - |

## soland#identity-tsp-bootstrap-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/identity/tsp-bootstrap.spec.ts:13 | alice and bob_extern bootstrap TSP relationship; alice sends Contrix invite via TSP; bob_extern verifies + ACKs | e2e/scenarios/identity/tsp-bootstrap.md | - |
| 2026Q3 | tracked | e2e/tests/identity/tsp-bootstrap.spec.ts:55 | E2.1 TSP endpoint unreachable → client falls back to HTTPS JWE; invite still delivers; audit logs transport.fallback{from:tsp,to:https-jwe} | e2e/scenarios/identity/tsp-bootstrap.md | - |
| 2026Q3 | tracked | e2e/tests/identity/tsp-bootstrap.spec.ts:71 | E2.2 VID resolver degraded (no witness) → TSP relationship's trust_level downgrades to 'degraded_no_witness'; signature still validates but trust drops | e2e/scenarios/identity/tsp-bootstrap.md | - |
| 2026Q3 | tracked | e2e/tests/identity/tsp-bootstrap.spec.ts:90 | E2.3 metadata privacy via nested message: an intermediary relay sees pairwise VID + payload_hash only — no vid_local, no inner operation, no plaintext payload | e2e/scenarios/identity/tsp-bootstrap.md | - |

## soland#identity-webvh-rotation-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/identity/webvh-rotation.spec.ts:12 | alice rotates her did:webvh controlling key; new entry signed by old update key + witness; resolver returns updated verificationMethod | e2e/scenarios/identity/webvh-rotation.md | - |
| 2026Q3 | tracked | e2e/tests/identity/webvh-rotation.spec.ts:23 | alice's pre-rotation events still verify under old key; post-rotation events verify under new key (spec §6 rule 5) | e2e/scenarios/identity/webvh-rotation.md | - |
| 2026Q3 | tracked | e2e/tests/identity/webvh-rotation.spec.ts:33 | did.jsonl history chain grows by exactly one entry; entry hash chain links correctly | e2e/scenarios/identity/webvh-rotation.md | - |
| 2026Q3 | tracked | e2e/tests/identity/webvh-rotation.spec.ts:43 | E9.1 tampered prev_entry_hash makes resolver fail closed (degraded_no_witness must NOT mask integrity break) | e2e/scenarios/identity/webvh-rotation.md | - |
| 2026Q3 | tracked | e2e/tests/identity/webvh-rotation.spec.ts:53 | E9.2 hosting domain serves a DID Doc with mismatched SCID; resolver rejects (DNS hijack protection) | e2e/scenarios/identity/webvh-rotation.md | - |
| 2026Q3 | tracked | e2e/tests/identity/webvh-rotation.spec.ts:63 | E9.3 organization rotation requires N-of-M governance signatures; single-sig submission rejected | e2e/scenarios/identity/webvh-rotation.md | - |
| 2026Q3 | tracked | e2e/tests/identity/webvh-rotation.spec.ts:73 | E9.4 witness offline > 24h causes resolver to enter unresolvable state; new events rejected until witness recovers | e2e/scenarios/identity/webvh-rotation.md | - |
| 2026Q3 | tracked | e2e/tests/identity/webvh-rotation.spec.ts:83 | E9.5 emergency rotation using recovery key (no prev-key signature path) succeeds | e2e/scenarios/identity/webvh-rotation.md | - |

## soland#invites-third-party-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/invites/third-party.spec.ts:38 | alice issues cx.invite.third_party with token_commitment; plaintext email never leaves client | e2e/scenarios/invites/third-party.md | - |
| 2026Q3 | tracked | e2e/tests/invites/third-party.spec.ts:48 | mock verification service receives invite token via email; bob registers DID; verification service signs binding_proof | e2e/scenarios/invites/third-party.md | - |
| 2026Q3 | tracked | e2e/tests/invites/third-party.spec.ts:58 | bob submits cx.invite.claim with binding_proof + subject_proof; reducer accepts and converts to cx.invite.create + accept | e2e/scenarios/invites/third-party.md | - |
| 2026Q3 | tracked | e2e/tests/invites/third-party.spec.ts:68 | E3.1 expired token: reducer rejects claim with invite_expired | e2e/scenarios/invites/third-party.md | - |
| 2026Q3 | tracked | e2e/tests/invites/third-party.spec.ts:76 | E3.2 wrong DID claim (subject_proof != binding_proof.subject) rejected with binding_mismatch | e2e/scenarios/invites/third-party.md | - |
| 2026Q3 | tracked | e2e/tests/invites/third-party.spec.ts:84 | E3.3 double-claim: second claim of same token rejected (token consumed) | e2e/scenarios/invites/third-party.md | - |

## soland#kanban-end-to-end-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/kanban/end-to-end.spec.ts:108 | concurrent cross-list move: cas-register accepts one winner, rejects the other with cas_register_conflict | e2e/scenarios/kanban/end-to-end.md | - |
| 2026Q3 | tracked | e2e/tests/kanban/end-to-end.spec.ts:118 | cross-space contains relation rejected with reason=cross_space_structural_relation | e2e/scenarios/kanban/end-to-end.md | - |
| 2026Q3 | tracked | e2e/tests/kanban/end-to-end.spec.ts:134 | commenting on an archived flow is rejected by reducer (no writes on archived Flow) | e2e/scenarios/kanban/end-to-end.md | - |
| 2026Q3 | tracked | e2e/tests/kanban/end-to-end.spec.ts:144 | reordering lists (drag column) updates board's child_order cell | e2e/scenarios/kanban/end-to-end.md | - |

## soland#kanban-project-simulation-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/kanban/project-simulation.spec.ts:102 | E16.1 unassign emits cx.relation.tombstone; assignment no longer shows in card UI | e2e/scenarios/kanban/project-simulation.md | - |
| 2026Q3 | tracked | e2e/tests/kanban/project-simulation.spec.ts:112 | alice archives the entire board; archived board's cards become read-only; archive list view shows the board | e2e/scenarios/kanban/project-simulation.md | - |
| 2026Q3 | tracked | e2e/tests/kanban/project-simulation.spec.ts:61 | alice assigns Card 1 to bob via cx.relation.create assigned_to; bob's notifications surface the assignment | e2e/scenarios/kanban/project-simulation.md | - |
| 2026Q3 | tracked | e2e/tests/kanban/project-simulation.spec.ts:72 | status FSM: Card transitions todo → in_progress → done via cx.flow.update; invalid transition (todo → done direct) rejected by FSM cell | e2e/scenarios/kanban/project-simulation.md | - |
| 2026Q3 | tracked | e2e/tests/kanban/project-simulation.spec.ts:82 | due_date past today renders as overdue badge on the card UI | e2e/scenarios/kanban/project-simulation.md | - |
| 2026Q3 | tracked | e2e/tests/kanban/project-simulation.spec.ts:92 | E16.G concurrent assignment from two devices: relation profile on_conflict=deterministic_winner picks one; Card has exactly one active assignee | e2e/scenarios/kanban/project-simulation.md | - |

## soland#messaging-chat-advanced-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/messaging/chat-advanced.spec.ts:223 | reactions converge (OR-Set) and replies render with reply indicator | e2e/scenarios/messaging/chat-advanced.md | - |
| 2026Q3 | tracked | e2e/tests/messaging/chat-advanced.spec.ts:300 | E14.D mentions route notifications only to the mentioned actor | e2e/scenarios/messaging/chat-advanced.md | - |
| 2026Q3 | tracked | e2e/tests/messaging/chat-advanced.spec.ts:365 | E14.E poll create + vote + close (vote replacement per actor) | e2e/scenarios/messaging/chat-advanced.md | - |
| 2026Q3 | tracked | e2e/tests/messaging/chat-advanced.spec.ts:443 | E14.F typing indicator (cx.typing ephemeral) appears in peer view within 1s and clears after ttl_ms=5000 | e2e/scenarios/messaging/chat-advanced.md | - |
| 2026Q3 | tracked | e2e/tests/messaging/chat-advanced.spec.ts:485 | E14.G presence state propagates online/offline within 1s after page open/close | e2e/scenarios/messaging/chat-advanced.md | - |
| 2026Q3 | tracked | e2e/tests/messaging/chat-advanced.spec.ts:528 | E14.2 mention in E2EE space uses sidecar hash; server log does not contain mentionee.did plaintext | e2e/scenarios/messaging/chat-advanced.md | - |

## soland#messaging-read-receipts-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/messaging/read-receipts.spec.ts:214 | space disclosure=disabled: client does not send; Sync Service silently drops any inbound cx.receipt.read for the space | e2e/scenarios/messaging/read-receipts.md | - |
| 2026Q3 | tracked | e2e/tests/messaging/read-receipts.spec.ts:224 | actor-private read marker (cx.read.marker) syncs across alice's devices but does NOT broadcast to bob | e2e/scenarios/messaging/read-receipts.md | - |
| 2026Q3 | tracked | e2e/tests/messaging/read-receipts.spec.ts:234 | E22.1 high-frequency scroll: debounce window ≥1s; only a single receipt covering the highest visible event is emitted | e2e/scenarios/messaging/read-receipts.md | - |
| 2026Q3 | tracked | e2e/tests/messaging/read-receipts.spec.ts:244 | E22.3 multi-device receipt coordination: HLC tie-break decides which device's marker fans out for shared receipt | e2e/scenarios/messaging/read-receipts.md | - |

## soland#messaging-triad-collaboration-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/messaging/triad-collaboration.spec.ts:206 | alice + bob + carol drive space lifecycle, mutual messaging, late-join history visibility, and redact tombstone | e2e/scenarios/messaging/triad-collaboration.md | - |

## soland#models-core-object-invariants-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/models/core-object-invariants.spec.ts:149 | Phase B — stale precondition head_eq is rejected with failed_precondition and effects[] are NOT applied | e2e/scenarios/models/core-object-invariants.md | - |
| 2026Q3 | tracked | e2e/tests/models/core-object-invariants.spec.ts:221 | Phase C — cx.space.archive does NOT cascade; tombstone with live dependents fails; post-tombstone writes are rejected | e2e/scenarios/models/core-object-invariants.md | - |
| 2026Q3 | tracked | e2e/tests/models/core-object-invariants.spec.ts:277 | Phase D — has_default_view enforces many_to_one; duplicate Relation create is idempotent; cross-Realm contains rejected | e2e/scenarios/models/core-object-invariants.md | - |
| 2026Q3 | tracked | e2e/tests/models/core-object-invariants.spec.ts:403 | Phase E — Board projection on a fresh Space with no registered View returns the derived default (NOT 404); unknown renderer fails closed | e2e/scenarios/models/core-object-invariants.md | - |

## soland#models-morph-schema-migration-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/models/morph-schema-migration.spec.ts:245 | Phase A — cx.morph.schema_migrate with unsupported transformation_rules is hard-rejected | e2e/scenarios/models/morph-schema-migration.md | - |
| 2026Q3 | tracked | e2e/tests/models/morph-schema-migration.spec.ts:280 | Phase B — additive schema_refs[] migration accepted and v1 history stays bound to v1 schema | e2e/scenarios/models/morph-schema-migration.md | - |
| 2026Q3 | tracked | e2e/tests/models/morph-schema-migration.spec.ts:317 | Phase C — breaking / transformation migration requires opt-in profile + capability and emits schema_migration_breaking audit | e2e/scenarios/models/morph-schema-migration.md | - |
| 2026Q3 | tracked | e2e/tests/models/morph-schema-migration.spec.ts:357 | Phase D — deterministic transform vectors produce byte-equal output (gated on fixture availability) | e2e/scenarios/models/morph-schema-migration.md | - |

## soland#models-private-read-marker-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/models/private-read-marker.spec.ts:107 | alice's read marker syncs across devices via to-device; mark-all-read advances marker on all devices within sync window | e2e/scenarios/models/private-read-marker.md | - |
| 2026Q3 | tracked | e2e/tests/models/private-read-marker.spec.ts:128 | E10.1 multi-device read marker eventual consistency: device-2 may lag but converges to device-1's last write within bounded sync window (spec §3) | e2e/scenarios/models/private-read-marker.md | - |
| 2026Q3 | tracked | e2e/tests/models/private-read-marker.spec.ts:139 | E10.2 E2EE space notification redaction: server-side GET /api/v1/notifications exposes only envelope metadata (event_id, sender_did, ts, encrypted:true); message body stays sealed until the client decrypts locally | e2e/scenarios/models/private-read-marker.md | - |
| 2026Q3 | tracked | e2e/tests/models/private-read-marker.spec.ts:151 | E10.3 discussion realm read marker is isolated from parent space marker (account_data key m.read_marker:<realm_id> is per-realm) | e2e/scenarios/models/private-read-marker.md | - |

## soland#models-realm-links-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/models/realm-links.spec.ts:21 | alice declares governed_by link from team realm to governance realm; bob's violations get filtered via inherited policy; link rejection restores independence | e2e/scenarios/models/realm-links.md | - |
| 2026Q3 | tracked | e2e/tests/models/realm-links.spec.ts:263 | E6.2 multi-target narrowing: T governed_by G1 + G2 takes narrow (intersection) of inherited rules (spec §6.2 narrow-only) | e2e/scenarios/models/realm-links.md | - |
| 2026Q3 | tracked | e2e/tests/models/realm-links.spec.ts:336 | E6.3 capability non-propagation: alice has realm.admin in G; the governed_by link does NOT grant her admin in T (spec §5) | e2e/scenarios/models/realm-links.md | - |

## soland#spaces-knock-application-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/spaces/knock-application.spec.ts:100 | E6.A bob submits structured member.application after knocking; alice (with cx.space.join.review) sees the answers and accepts | e2e/scenarios/spaces/knock-application.md | - |
| 2026Q3 | tracked | e2e/tests/spaces/knock-application.spec.ts:112 | E6.B alice's cx.invite.create.refs[role=\"join_authorised_by\"] is required to point at a fresh review accept; reducer rejects re-used or stale refs | e2e/scenarios/spaces/knock-application.md | - |
| 2026Q3 | tracked | e2e/tests/spaces/knock-application.spec.ts:123 | E6.C mallory is rejected by alice and CANNOT re-knock until cooldown_after_reject (default 72h) elapses; cooldown gate independent of combinator | e2e/scenarios/spaces/knock-application.md | - |
| 2026Q3 | tracked | e2e/tests/spaces/knock-application.spec.ts:134 | E6.D max_open_applications_per_actor=1 — bob's second open application is rejected before review | e2e/scenarios/spaces/knock-application.md | - |
| 2026Q3 | tracked | e2e/tests/spaces/knock-application.spec.ts:145 | E6.E application_ttl expiry — application accepted past TTL is rejected even if reviewer signs accept | e2e/scenarios/spaces/knock-application.md | - |
| 2026Q3 | tracked | e2e/tests/spaces/knock-application.spec.ts:156 | E6.F reviewer loses cx.space.join.review between review accept and invite create; invite create MUST be rejected even though review already accepted | e2e/scenarios/spaces/knock-application.md | - |
| 2026Q3 | tracked | e2e/tests/spaces/knock-application.spec.ts:167 | E6.G applicant_visibility=reviewer_only — non-reviewer members CANNOT read application answers; sync service returns 403 and writes cx.audit.accessed | e2e/scenarios/spaces/knock-application.md | - |

## soland#spaces-knock-auto-resolve-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/spaces/knock-auto-resolve.spec.ts:10 | alice sets join_rule=knock_restricted with gates=[claim_required(auto), challenge_response(auto)]; bob submits cx.member.state{join, gate_proofs[]} and joins directly | e2e/scenarios/spaces/knock-auto-resolve.md | - |
| 2026Q3 | tracked | e2e/tests/spaces/knock-auto-resolve.spec.ts:21 | mallory without the required VC: gate_proofs[].g-vc invalid; reducer rejects with failed_precondition + g-vc gate id | e2e/scenarios/spaces/knock-auto-resolve.md | - |
| 2026Q3 | tracked | e2e/tests/spaces/knock-auto-resolve.spec.ts:29 | E6.2.2 challenge_proof older than max_proof_age=5min: rejected with challenge_failed | e2e/scenarios/spaces/knock-auto-resolve.md | - |
| 2026Q3 | tracked | e2e/tests/spaces/knock-auto-resolve.spec.ts:37 | cooldown gate independent of combinator: bob leaves then immediately re-applies → rejected with cooldown_gate_blocking | e2e/scenarios/spaces/knock-auto-resolve.md | - |
| 2026Q3 | tracked | e2e/tests/spaces/knock-auto-resolve.spec.ts:47 | combinator=any: bob satisfies only g-vc → still accepted; mallory satisfies only g-captcha → also accepted (typical knock_restricted hybrid) | e2e/scenarios/spaces/knock-auto-resolve.md | - |

## soland#sync-offline-conflict-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/sync/offline-conflict.spec.ts:102 | bob clicks prefer-safer-side-button to repair; reducer accepts repair Move with state_witness + inclusion_proof; banner clears | e2e/scenarios/sync/offline-conflict.md | - |
| 2026Q3 | tracked | e2e/tests/sync/offline-conflict.spec.ts:112 | long offline → on reconnect, pull-operations backfills missing events; bob's timeline catches up to head | e2e/scenarios/sync/offline-conflict.md | - |
| 2026Q3 | tracked | e2e/tests/sync/offline-conflict.spec.ts:68 | bob composes a message while offline; on reconnect the message persists and is visible to alice | e2e/scenarios/sync/offline-conflict.md | - |
| 2026Q3 | tracked | e2e/tests/sync/offline-conflict.spec.ts:82 | during offline window alice writes; on bob's reconnect both writes are visible with deterministic ordering | e2e/scenarios/sync/offline-conflict.md | - |
| 2026Q3 | tracked | e2e/tests/sync/offline-conflict.spec.ts:92 | concurrent writes to the same cas-register cell trigger bottom_expose; bottom-cells-banner shows the conflict | e2e/scenarios/sync/offline-conflict.md | - |

## soland#sync-service-surface-contract-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/sync/service-surface-contract.spec.ts:155 | Phase A.E1: claim_kind partition does not leak between claimed_profiles and verified_profiles | e2e/scenarios/sync/service-surface-contract.md | - |
| 2026Q3 | tracked | e2e/tests/sync/service-surface-contract.spec.ts:178 | Phase B: unknown path returns 404 unrecognized_endpoint with standard error envelope | e2e/scenarios/sync/service-surface-contract.md | - |
| 2026Q3 | tracked | e2e/tests/sync/service-surface-contract.spec.ts:205 | Phase C: list endpoint pagination cursor is opaque, gap-free, and non-overlapping across pages | e2e/scenarios/sync/service-surface-contract.md | - |
| 2026Q3 | tracked | e2e/tests/sync/service-surface-contract.spec.ts:235 | Phase D: Idempotency-Key replay returns the cached first response; same key + different body returns duplicate_conflict | e2e/scenarios/sync/service-surface-contract.md | - |
| 2026Q3 | tracked | e2e/tests/sync/service-surface-contract.spec.ts:271 | Phase E: event requiring an undeclared feature is rejected with unsupported_feature (fail-closed) | e2e/scenarios/sync/service-surface-contract.md | - |

## soland#sync-sovereign-deployment-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/sync/sovereign-deployment.spec.ts:16 | alice_internal and bob_external collaborate in enclave realm; bob cannot escape; exit triggers audit log | e2e/scenarios/sync/sovereign-deployment.md | - |
| 2026Q3 | tracked | e2e/tests/sync/sovereign-deployment.spec.ts:54 | E7.1 escape attempt rejected: bob cannot reach main domain via directory / direct API / enclave proxy | e2e/scenarios/sync/sovereign-deployment.md | - |
| 2026Q3 | tracked | e2e/tests/sync/sovereign-deployment.spec.ts:75 | E7.2 network outage: soland_main <-> soland_enclave 失联时 enclave 走 store-and-forward,而非客户端 offline outbox | e2e/scenarios/sync/sovereign-deployment.md | - |
| 2026Q3 | tracked | e2e/tests/sync/sovereign-deployment.spec.ts:99 | E7.3 enclave DID resolver policy: bob 的 DID 必须通过 enclave 的 trust chain 验证(不是 main 的) | e2e/scenarios/sync/sovereign-deployment.md | - |

## soland#sync-transport-negotiation-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/sync/transport-negotiation.spec.ts:186 | E8.1 signature expiry + key rotation: soland_a signs with an expired key; soland_b returns 401 with key_rotation_hint; α re-signs with current key and succeeds | e2e/scenarios/sync/transport-negotiation.md | - |
| 2026Q3 | tracked | e2e/tests/sync/transport-negotiation.spec.ts:208 | E8.2 multi-hop relay: α → relay → β; β verifies BOTH the relay's outer RFC 9421 signature AND the inner EventEnvelope actor signature; either failure rejects the batch | e2e/scenarios/sync/transport-negotiation.md | - |
| 2026Q3 | tracked | e2e/tests/sync/transport-negotiation.spec.ts:235 | E8.3 binding negotiation timeout: α requests WebSocket upgrade; β does not respond within 30s; α cancels and falls back to HTTP/JSON | e2e/scenarios/sync/transport-negotiation.md | - |
| 2026Q3 | tracked | e2e/tests/sync/transport-negotiation.spec.ts:89 | soland_a and soland_b negotiate HTTP → WebSocket → TSP with proper RFC 9421 signing throughout; fallback to HTTP on WebSocket failure | e2e/scenarios/sync/transport-negotiation.md | - |

## soland#workflows-daily-standup-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/workflows/daily-standup.spec.ts:109 | E-standup.offline pat is offline mid-post; reconnect flushes the outbox | e2e/scenarios/workflows/daily-standup.md | - |
| 2026Q3 | tracked | e2e/tests/workflows/daily-standup.spec.ts:119 | E-standup.redact lin redacts their own standup after spotting a wrong template | e2e/scenarios/workflows/daily-standup.md | - |

## soland#workflows-incident-response-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/workflows/incident-response.spec.ts:113 | E-incident.status status FSM rejects Resolved before Mitigated and records each transition in audit | e2e/scenarios/workflows/incident-response.md | - |
| 2026Q3 | tracked | e2e/tests/workflows/incident-response.spec.ts:158 | E-incident.priority SEV-1 priority bypasses DnD for on-call but not for observers | e2e/scenarios/workflows/incident-response.md | - |
| 2026Q3 | tracked | e2e/tests/workflows/incident-response.spec.ts:219 | E-incident.postmortem links a document morph to the incident and preserves versioned final report | e2e/scenarios/workflows/incident-response.md | - |
| 2026Q3 | tracked | e2e/tests/workflows/incident-response.spec.ts:22 | on-call opens SEV-2 war room; backend diagnoses; comms publishes sanitized updates; on-call edits final timeline | e2e/scenarios/workflows/incident-response.md | - |

## soland#workflows-kanban-week-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/workflows/kanban-week.spec.ts:128 | E-kanbanweek.1 restored card lands at the end of its original column, preserving rank | e2e/scenarios/workflows/kanban-week.md | - |
| 2026Q3 | tracked | e2e/tests/workflows/kanban-week.spec.ts:139 | E-kanbanweek.2 archive an entire list (column-level archive button) | e2e/scenarios/workflows/kanban-week.md | - |

## soland#workflows-sprint-planning-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/workflows/sprint-planning.spec.ts:108 | E-sprint.kanban mei builds a Backlog + Todo + Doing + Done kanban and promotes 3 stories | e2e/scenarios/workflows/sprint-planning.md | - |
| 2026Q3 | tracked | e2e/tests/workflows/sprint-planning.spec.ts:120 | E-sprint.crossuser bob + carol see the same kanban as mei after she edits the board | e2e/scenarios/workflows/sprint-planning.md | - |
| 2026Q3 | tracked | e2e/tests/workflows/sprint-planning.spec.ts:130 | E-sprint.archiveboard mei archives the entire sprint board at end of week | e2e/scenarios/workflows/sprint-planning.md | - |

## soland#workflows-support-escalation-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/workflows/support-escalation.spec.ts:131 | E-support.kanban alex tracks ticket on a Triage → In Progress → Resolved kanban | e2e/scenarios/workflows/support-escalation.md | - |
| 2026Q3 | tracked | e2e/tests/workflows/support-escalation.spec.ts:143 | E-support.redact alex redacts a reply that leaked PII; tombstone replaces body for both | e2e/scenarios/workflows/support-escalation.md | - |

## soland#workflows-team-onboarding-gap

| expected_live_by | status | file:line | title | user_promise | missing |
|---|---|---|---|---|---|
| 2026Q3 | tracked | e2e/tests/workflows/team-onboarding.spec.ts:108 | E-onboarding.2 mei edits welcome twice; write-status reflects revision count | e2e/scenarios/workflows/team-onboarding.md | - |
| 2026Q3 | tracked | e2e/tests/workflows/team-onboarding.spec.ts:98 | E-onboarding.1 mei pins the welcome message so yuki keeps seeing it at the top | e2e/scenarios/workflows/team-onboarding.md | - |
