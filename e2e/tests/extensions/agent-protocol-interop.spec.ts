// Agent Protocol Interop — external A2A/ACP handoff full chain
// Contract: e2e/scenarios/extensions/agent-protocol-interop.md
// Spec: extensions/agent-protocol-interop.md §4 (upgrade trigger), §5.1
//       (cx.agent.endpoint), §5.2 (protocol_session.start), §5.3
//       (protocol_session.status throttle), §5.4 (protocol_session.result +
//       result_objects/artifacts/transcript hash), §6 step 4 (endpoint
//       validation normative MUST), §7 (capability actions + constraint),
//       §8 (security boundary), §9 (audit_mode), §11 (adapter registry),
//       §12 (failure codes).
//
// soland gap: external HTTP handoff (RFC 9421 + Content-Digest + DID
// Document service binding) 未实现 — agent_bridge.rs 目前只跑 in-process
// echo (REFERENCE_AGENT_AUDIT_ED25519_SEED). `POST /api/v1/agents/discover`
// 与 `POST /api/v1/agents/sessions(/:id/status)` 端点未上线;
// claimed_profiles 也尚未声明 `cx.profile.agent_runtime.v1`。
//
// yougen gap: /agents 的 create-session/publish affordances 当前未对接 soland
// capability grant API;publish modal 的 attribution 分支需要 source authority
// FSM 状态配合才出现。
//
// harness gap: 没有 mock-agent-runtime.mjs。短期里 Phase A 的 endpoint
// discovery 仍可走 in-process echo 验证;Phase C/D/E 全部 fixme,直到
// `cotest/scripts/mock-agent-runtime.mjs` + `mockAgentRuntimeBaseUrl()`
// helper 落地。

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("agent protocol interop", () => {
  test("yougen /agents panel mounts (harness reachability smoke)", async ({
    browser,
    request,
  }, testInfo) => {
    // Live probe — has to keep working even before the agent-runtime
    // mock and soland's external handoff path land. We assert two
    // surface invariants:
    //
    //   1. yougen's `/agents` route mounts and renders `agents-panel`
    //      (real testid from yougen/src/views/agents.rs::AgentsPanel).
    //      Without this surface the spec's Phase A endpoint registry
    //      flow has no UI anchor.
    //   2. soland's `/api/v1/server/describe` responds with 200 + a
    //      JSON body (current shape — claimed_profiles will eventually
    //      include `cx.profile.agent_runtime.v1`, but today we don't
    //      assert that contents).
    //
    // Anything tighter (e.g. asserting agent endpoints in the panel,
    // or that describe claims agent_runtime) belongs in the fixme
    // tests below.
    const stamp = Date.now();
    const alice = uniqueUser(`agent-handoff-alice-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const describe = await request.get(`${solandBaseUrl()}/api/v1/server/describe`);
    expect(describe.status()).toBe(200);
    const describeBody = await describe.json();
    expect(describeBody).toBeTruthy();
    await testInfo.attach("server-describe", {
      body: JSON.stringify(describeBody, null, 2),
      contentType: "application/json",
    });

    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    try {
      // yougen routes.rs §"/agents" → AgentsPanel; testid pinned in
      // yougen/src/views/agents.rs line 226 (`data-testid="agents-panel"`).
      // Relative path; Playwright baseURL points at yougen
      // (cotest/e2e/playwright.config.ts).
      await alicePage.page.goto("/agents", { waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("agents-panel")).toBeVisible({
        timeout: 120_000,
      });
      // The empty-state testid is also stable (`agent-endpoint-empty`)
      // and proves the panel actually rendered the endpoint list region,
      // not just a shell. Skip the assertion if a prior test left an
      // endpoint registered — we only need at least one of empty-state
      // or endpoint row to be visible.
      const empty = alicePage.page.getByTestId("agent-endpoint-empty");
      const rows = alicePage.page.getByTestId("agent-endpoint-row");
      const eitherVisible =
        (await empty.count()) > 0 || (await rows.count()) > 0;
      expect(eitherVisible).toBe(true);
    } finally {
      await alicePage.close();
    }
  });

  test.fixme(
    // @blocking-on: soland#extensions-agent-protocol-interop-gap
    // @user-promise: e2e/scenarios/extensions/agent-protocol-interop.md
    // @expected-live-by: 2026Q3
    "Phase A — agent endpoint discovery via cx.agent.endpoint + DID Document service binding",
    async ({ browser, request }) => {
      // spec: extensions/agent-protocol-interop.md §5.1 (cx.agent.endpoint
      // declares agent_card_url / metadata_url / transport / auth),
      // §6 step 1 (requesting agent queries DID service endpoint /
      // AgentCard / ACP metadata), §7 (`cx.agent.protocol.discover`
      // capability), §11 (adapter registry: a2a / acp / mcp_bridge /
      // http_custom).
      //
      // Pseudo:
      //   const alice = uniqueUser("agent-handoff-alice-...");
      //   const localAgent = uniqueUser("local-agent-handoff-...");
      //   const remoteAgent = uniqueUser("agent-handoff-remote-...");
      //   await Promise.all([
      //     ensureRegistered(request, alice),
      //     ensureRegistered(request, localAgent),
      //     ensureRegistered(request, remoteAgent),
      //   ]);
      //
      //   // 1. alice opens /agents, registers remoteAgent.did via the
      //   //    agent-register-form (testid agent-register-submit-button).
      //   //    Assert agent-endpoint-row appears with remoteAgent.did.
      //
      //   // 2. harness: GET /api/v1/identity/${remoteAgent.did}/did-document
      //   //    → assert service[].serviceEndpoint byte-equals the
      //   //      mock-agent-runtime base URL (spec §6 step 4 host pinning).
      //
      //   // 3. localAgent token: POST /api/v1/agents/discover
      //   //    { agent_id: remoteAgent.did }
      //   //    → expect 200 with { supported_protocols: ["a2a","acp"], ... }
      //   //      where supported_protocols ⊆ {"a2a","acp","mcp_bridge",
      //   //      "http_custom"} (spec §11).
      //
      //   // TODO: createAgentSession(...) helper not yet implemented;
      //   //       the discover endpoint itself is also a soland gap.
      void browser;
      void request;
    },
  );

  test.fixme(
    // @blocking-on: soland#extensions-agent-protocol-interop-gap
    // @user-promise: e2e/scenarios/extensions/agent-protocol-interop.md
    // @expected-live-by: 2026Q3
    "Phase B — capability approval with allowed_endpoints / requires_human_approval gate",
    async ({ browser, request }) => {
      // spec: extensions/agent-protocol-interop.md §4 (upgrade MUST be
      // explicit + authorizable), §7 (capability constraint:
      // allowed_protocols / allowed_endpoints / max_duration_seconds /
      // max_artifact_bytes / requires_human_approval / egress_policy),
      // §8 (启动前 capability 检查), §12 (`policy_denied` failure code).
      //
      // Pseudo:
      //   // 1. alice opens /agents, starts a new protocol session,
      //   //    and fills constraint:
      //   //       allowed_protocols = ["a2a"]
      //   //       allowed_endpoints = [exact mock base URL]
      //   //       max_duration_seconds = 3600
      //   //       max_artifact_bytes = 10_485_760
      //   //       egress_policy = "metadata_only"
      //   //       requires_human_approval = true
      //   //       audit_mode = "summary_and_artifacts"
      //
      //   // 2. Assert a human-approval gate is shown before publish-modal-confirm.
      //   //    Click confirm → POST creates `cx.capability.grant.create`.
      //
      //   // 3. harness: GET soland sync; find the capability.grant.create
      //   //    event; assert payload.actions includes
      //   //    "cx.agent.protocol_session.start" and
      //   //    payload.constraint.allowed_endpoints is single-valued and
      //   //    points exactly at the mock runtime base URL (no wildcard).
      //
      //   // 4. Negative: localAgent calls POST /api/v1/agents/sessions
      //   //    WITHOUT capability_grant_ref → expect HTTP 4xx with
      //   //    error.code === "policy_denied" (spec §12).
      //
      //   // TODO: helper for capability grant create not yet implemented;
      //   //       yougen "create task" modal not yet wired to soland.
      void browser;
      void request;
    },
  );

  test.fixme(
    // @blocking-on: soland#extensions-agent-protocol-interop-gap
    // @user-promise: e2e/scenarios/extensions/agent-protocol-interop.md
    // @expected-live-by: 2026Q3
    "Phase C — invocation handoff with throttled status transcript",
    async ({ browser, request }) => {
      // spec: extensions/agent-protocol-interop.md §5.2 (cx.agent.protocol_session.start
      // fields), §5.3 (status events + standard enum negotiating / accepted /
      // working / input_required / blocked / completed / failed / cancelled /
      // expired), §6 step 5-7, §9 (`audit_mode`: status_only /
      // summary_and_artifacts / full_transcript_hash / full_transcript).
      //
      // Pseudo:
      //   // 1. localAgent token: POST /api/v1/agents/sessions
      //   //    body = { session_id, counterparty_agent: remoteAgent.did,
      //   //             protocol: "a2a", endpoint_ref,
      //   //             capability_grant: cg, audit_mode: "summary_and_artifacts",
      //   //             allowed_artifact_types: ["text","json"],
      //   //             max_duration_seconds: 3600 }
      //
      //   // 2. Assert 200 + GET /api/v1/account/subscribe?catchup=true finds
      //   //    `cx.agent.protocol_session.start` immediately.
      //
      //   // 3. soland's agent_bridge.rs handshakes with mock-agent-runtime
      //   //    via reqwest (RFC 9421 HTTP Message Signature + Content-Digest).
      //
      //   // 4. mock-agent-runtime callbacks POST /api/v1/agents/sessions/
      //   //    ${sessionId}/status at least 3 times within 3s with status:
      //   //    negotiating → accepted → working.
      //
      //   // 5. yougen /agents agent-session-row updates status text from
      //   //    "negotiating" to "working" within 3s of last callback.
      //
      //   // 6. Assert under audit_mode = "summary_and_artifacts" the
      //   //    persisted status event count ≤ ~3 (throttled), NOT one
      //   //    per token; under "status_only" the count ≤ 1.
      //
      //   // TODO: createAgentSession(...) helper not yet implemented;
      //   //       mock-agent-runtime not yet implemented either.
      void browser;
      void request;
    },
  );

  test.fixme(
    // @blocking-on: soland#extensions-agent-protocol-interop-gap
    // @user-promise: e2e/scenarios/extensions/agent-protocol-interop.md
    // @expected-live-by: 2026Q3
    "Phase D — publish-to-source flow lands Flow + Morph with attribution",
    async ({ browser, request }) => {
      // spec: extensions/agent-protocol-interop.md §5.4 (result_objects /
      // artifacts / external_transcript_digest; v1 object types: flow /
      // message / morph / blob), §6 step 8-9.
      //
      // Pseudo:
      //   // 1. mock-agent-runtime POST result back with body:
      //   //    {
      //   //      session_id, status: "completed",
      //   //      result_objects: [{ object_type: "flow",
      //   //                         object_ref: "cx:flow:<uuid>",
      //   //                         track: "synthesis",
      //   //                         role: "primary_result" }],
      //   //      artifacts: [{ artifact_type: "text",
      //   //                    object_ref: "cx:morph:<uuid>",
      //   //                    hash: "sha256:<hex>" }],
      //   //      external_transcript_digest: "sha256:<hex>",
      //   //      completed_at: "<iso>"
      //   //    }
      //
      //   // 2. soland (agent_bridge.rs) signs an Ed25519 audit_binding
      //   //    using REFERENCE_AGENT_AUDIT_ED25519_SEED. Assert the
      //   //    event payload has:
      //   //      audit_binding.binding_kind === "ed25519_v1"
      //   //      audit_binding.key_id === "soland.reference.agent_echo.ed25519_v1"
      //
      //   // 3. yougen /agents agent-incoming-result-row shows
      //   //    agent-audit-verify-badge text === "audit valid"
      //   //    (verifies via contrix_sdk::agent_binding).
      //
      //   // 4. alice clicks /agents session detail (testid
      //   //    agent-session-detail) → agent-session-publish → publish
      //   //    modal opens (testid publish-modal-backdrop) → choose
      //   //    publish-modal-signer-self-with-attribution → confirm.
      //
      //   // 5. Source space gains a new Flow whose fields.workflow_type
      //   //    includes "synthesis"; Flow's create event actor_id is
      //   //    alice.did but `attribution` includes remoteAgent.did
      //   //    (spec §5.4 publish semantics).
      //
      //   // TODO: publishToSource(...) helper not yet implemented.
      void browser;
      void request;
    },
  );

  test.fixme(
    // @blocking-on: soland#extensions-agent-protocol-interop-gap
    // @user-promise: e2e/scenarios/extensions/agent-protocol-interop.md
    // @expected-live-by: 2026Q3
    "Phase E — audit chain start → status* → result is contiguous and verifiable",
    async ({ browser, request }) => {
      // spec: extensions/agent-protocol-interop.md §5 (full event
      // family), §9 (audit modes), §13 (Contrix is durable
      // coordination / authorization / audit layer).
      //
      // Pseudo:
      //   // 1. GET /api/v1/account/subscribe?catchup=true; filter to this
      //   //    session_id's events; assert ordering matches
      //   //    start → status (negotiating) → status (accepted) →
      //   //    status (working) → result (completed). No status
      //   //    after result. No status before start.
      //
      //   // 2. For each consecutive pair, assert event[i].prev_event_id
      //   //    === event[i-1].event_id (hash chain).
      //
      //   // 3. Run contrix_sdk::agent_binding::verify_audit_binding_by_kind
      //   //    against the result event's payload. Expect
      //   //    AuditBindingVerifyOutcome::Valid (matches yougen's
      //   //    verify_agent_audit_binding helper).
      //
      //   // 4. On yougen /agents, assert agent-incoming-status text
      //   //    matches /\d+ result event\(s\) \(\d+ new since last poll\)/
      //   //    at least once (proves the 4s polling loop in
      //   //    AgentsPanel picked up the new result).
      //
      //   // 5. testInfo.attach("agent-handoff-audit-chain.json", events)
      //   //    so failures are inspectable.
      //
      //   // TODO: verifyAuditChain(...) helper not yet implemented.
      void browser;
      void request;
    },
  );
});
