// Agent Protocol Interop — external A2A/ACP handoff full chain
// Contract: e2e/scenarios/extensions/agent-protocol-interop.md
// Spec: extensions/agent-protocol-interop.md §4 (upgrade trigger), §5.1
//       (ck.agent.endpoint), §5.2 (interop_session.start), §5.3
//       (interop_session.status throttle), §5.4 (interop_session.result +
//       result_objects/artifacts/transcript hash), §6 step 4 (endpoint
//       validation normative MUST), §7 (capability actions + constraint),
//       §8 (security boundary), §9 (audit_mode), §11 (adapter registry),
//       §12 (failure codes).
//
// Naming note: the spec truth source + arkret_sdk use
// `ck.agent.interop_session.*` (NOT the older `protocol_session.*` draft
// term that earlier scaffolding referenced). All kinds below follow the
// spec / SDK.
//
// soland status: agent_bridge.rs runs the full start -> status(working) ->
// result(completed) fan-out with an Ed25519 `audit_binding`, an outbound
// HTTP path (POST to a registered endpoint_url), and a fail-closed path.
// `POST /_arkret/self/agents/discover` reflects the `ck.agent.endpoint`
// projection (supported_protocols / agent_card_url / metadata_url). The
// external runtime is represented by `mock-agent-runtime.mjs`
// (`mockAgentRuntimeBaseUrl()`).
//
// Promotion split for this scenario:
//   * Phase A (discovery) + Phase E (audit chain) are promoted to live
//     API-level tests — they need only soland + the events API + the
//     in-process / outbound bridge, no inkson UI.
//   * Phase B (human-approval gate), Phase C (agent-session-row status
//     stream), and Phase D (publish modal + attribution Strand) stay
//     fixme because their user-facing assertions are anchored on inkson
//     /agents UI affordances (publish-modal-*, agent-session-row,
//     agent-audit-verify-badge, agent-incoming-poll-tick) that are not
//     wired to the soland capability/session API yet. The soland building
//     blocks they depend on (discover endpoint, mock runtime, capability
//     gate on start) are in place; promotion is a inkson-UI task.

import { expect, test } from "@playwright/test";
import { mockAgentRuntimeBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  createRealmApi,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  uuidV7,
} from "../../helpers/soland-api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

// §11 adapter registry ids. supported_protocols returned by discover MUST
// be a subset of this set.
const ADAPTER_REGISTRY_IDS = ["a2a", "acp", "mcp_bridge", "http_custom"];

function eventKind(event: Record<string, unknown>): string {
  return String(event.kind ?? event.event_kind ?? "");
}

test.describe.configure({ mode: "serial" });

test.describe("agent protocol interop", () => {
  test("inkson /agents panel mounts (harness reachability smoke)", async ({
    browser,
    request,
  }, testInfo) => {
    // Live probe — asserts two surface invariants:
    //   1. inkson's `/agents` route mounts and renders `agents-panel`.
    //   2. soland's `/_arkret/describe` responds 200, and its
    //      `claimed_profiles` now includes `ck.profile.agent_runtime.v1`
    //      (the extension profile that backs this scenario).
    const stamp = Date.now();
    const describe = await request.get(`${solandBaseUrl()}/_arkret/describe`);
    expect(describe.status()).toBe(200);
    const describeBody = await describe.json();
    expect(describeBody).toBeTruthy();
    const claimedIds: string[] = (describeBody.claimed_profiles ?? [])
      .map((entry: { profile_id?: string }) => entry.profile_id)
      .filter(Boolean);
    expect(
      claimedIds,
      "soland describe must claim the agent_runtime extension profile",
    ).toContain("ck.profile.agent_runtime.v1");
    await testInfo.attach("server-describe", {
      body: JSON.stringify(describeBody, null, 2),
      contentType: "application/json",
    });

    const aliceFlow = await openDpopUserPage(
      browser,
      request,
      `agent-handoff-alice-${stamp}`,
      { prepareMlsDevice: false },
    );
    if (!aliceFlow) {
      assertJointStackNotRequired("agent panel browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceFlow.page;
    try {
      await alicePage.page.goto("/agents", { waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("agents-panel")).toBeVisible({
        timeout: 120_000,
      });
      const empty = alicePage.page.getByTestId("agent-endpoint-empty");
      const rows = alicePage.page.getByTestId("agent-endpoint-row");
      const eitherVisible =
        (await empty.count()) > 0 || (await rows.count()) > 0;
      expect(eitherVisible).toBe(true);
    } finally {
      await alicePage.close();
    }
  });

  test("Phase A — agent endpoint discovery via ck.agent.endpoint + adapter registry", async ({
    request,
  }, testInfo) => {
    // spec: §5.1 (ck.agent.endpoint declares per-endpoint protocol /
    // agent_card_url / metadata_url), §7 (`ck.agent.protocol.discover`
    // capability), §11 (adapter registry: a2a / acp / mcp_bridge /
    // http_custom).
    const stamp = Date.now();
    const alice = uniqueUser(`agent-handoff-alice-a-${stamp}`);
    const remoteAgent = uniqueUser(`agent-handoff-remote-a-${stamp}`);
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, remoteAgent),
    ]);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `agent-discovery-${stamp}`,
    });

    // 1. Register the remote agent's external protocol endpoints via
    //    `ck.agent.endpoint` (spec §5.1). Declares a2a + acp with distinct
    //    agent_card_url / metadata_url, plus a host-pinned endpoint_url
    //    that points at the mock runtime when available.
    const cardBase = mockAgentRuntimeBaseUrl() ?? "https://agent.example";
    const endpointPayload = {
      agent_id: remoteAgent.did,
      endpoints: [
        {
          protocol: "a2a",
          version: "1.x",
          agent_card_url: `${cardBase}/.well-known/agent-card.json`,
          endpoint_url: `${cardBase}/v1/a2a/tasks`,
          transport: ["https", "sse"],
          auth: ["did-http-signature"],
        },
        {
          protocol: "acp",
          version: "0.x",
          metadata_url: `${cardBase}/info`,
          transport: ["https", "sse"],
          auth: ["bearer", "did-http-signature"],
        },
      ],
    };
    const endpointResp = await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.agent.endpoint",
        schemaId: "ck.schema.agent.v1",
        payload: endpointPayload,
      }),
      { context: "register ck.agent.endpoint" },
    );
    expect(endpointResp.status).toBe("accepted");

    // 2. Discover: POST /_arkret/self/agents/discover { agent_id }.
    //    Assert supported_protocols ⊆ the §11 adapter registry, and that
    //    a2a + acp both surface; assert agent_card_url / metadata_url
    //    round-trip from the ck.agent.endpoint declaration.
    const discoverResp = await request.post(
      `${solandBaseUrl()}/_arkret/self/agents/discover`,
      {
        headers: { authorization: `Bearer ${aliceToken}` },
        data: { agent_id: remoteAgent.did },
      },
    );
    expect(
      discoverResp.status(),
      `discover returned ${discoverResp.status()}: ${await discoverResp.text()}`,
    ).toBe(200);
    const discover = await discoverResp.json();
    await testInfo.attach("agent-discover.json", {
      body: JSON.stringify(discover, null, 2),
      contentType: "application/json",
    });
    expect(discover.agent_id).toBe(remoteAgent.did);
    expect(Array.isArray(discover.supported_protocols)).toBe(true);
    for (const protocol of discover.supported_protocols) {
      expect(
        ADAPTER_REGISTRY_IDS,
        `discover surfaced protocol ${protocol} outside the §11 adapter registry`,
      ).toContain(protocol);
    }
    expect(discover.supported_protocols).toEqual(
      expect.arrayContaining(["a2a", "acp"]),
    );
    expect(discover.agent_card_url).toBe(
      `${cardBase}/.well-known/agent-card.json`,
    );
    expect(discover.metadata_url).toBe(`${cardBase}/info`);

    // 3. Negative: discover an agent with no accepted ck.agent.endpoint
    //    fails closed with HTTP 404 + error.code=discovery_failed (§12).
    const unknown = uniqueUser(`agent-handoff-unknown-${stamp}`);
    const missingResp = await request.post(
      `${solandBaseUrl()}/_arkret/self/agents/discover`,
      {
        headers: { authorization: `Bearer ${aliceToken}` },
        data: { agent_id: unknown.did },
      },
    );
    expect(missingResp.status()).toBe(404);
    const missingBody = await missingResp.json();
    expect(missingBody?.error?.code ?? missingBody?.code).toBe(
      "discovery_failed",
    );
  });

  test("Phase E — audit chain start → status → result is contiguous and verifiable", async ({
    request,
  }, testInfo) => {
    // spec: §5 (full event family), §5.3 (status enum + transitions),
    // §5.4 (result + audit_binding), §9 (audit modes), §13 (Arkret is the
    // durable audit layer). Drives the in-process echo bridge: submitting
    // `ck.agent.interop_session.start` fans out status(working) +
    // result(completed) carrying the Ed25519 audit_binding.
    const stamp = Date.now();
    const alice = uniqueUser(`agent-handoff-alice-e-${stamp}`);
    const remoteAgent = uniqueUser(`agent-handoff-remote-e-${stamp}`);
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, remoteAgent),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `agent-audit-chain-${stamp}`,
    });

    // Register the agent endpoint (no endpoint_url → in-process echo path,
    // which is the deterministic signed-result path we pin here).
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.agent.endpoint",
        schemaId: "ck.schema.agent.v1",
        payload: {
          agent_id: remoteAgent.did,
          endpoints: [{ protocol: "a2a" }],
        },
      }),
      { context: "register endpoint for audit chain" },
    );

    // Submit interop_session.start. capability_grant is a required payload
    // field (soland AGENT_SESSION_START_REQUIREMENTS); omit it and the
    // submit is rejected before the bridge runs.
    // Session object id pattern per agent.schema.json:
    // ck:agent_interop_session:<uuidv7> (not a typedId OperationKind).
    const sessionId = `ck:agent_interop_session:${uuidV7()}`;
    const startResp = await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.agent.interop_session.start",
        schemaId: "ck.schema.agent.v1",
        payload: {
          session_id: sessionId,
          counterparty_agent: remoteAgent.did,
          protocol: "a2a",
          capability_grant: typedId("grant"),
          audit_mode: "summary_and_artifacts",
          params: { op: "synthesize", doc: "audit-chain" },
        },
      }),
      { context: "submit interop_session.start" },
    );
    expect(startResp.status).toBe("accepted");

    // Poll the events surface until the result lands (the bridge appends
    // status + result; result may be a tick behind the start response).
    const eventsUrl = `${solandBaseUrl()}/_arkret/self/events?realms=${encodeURIComponent(realmId)}&limit=100`;
    let sessionEvents: Array<Record<string, unknown>> = [];
    for (let attempt = 0; attempt < 30; attempt++) {
      const resp = await request.get(eventsUrl, {
        headers: { authorization: `Bearer ${aliceToken}` },
      });
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      const list: Array<Record<string, unknown>> = body.events ?? [];
      sessionEvents = list.filter(
        (event) =>
          (event.payload as Record<string, unknown> | undefined)?.session_id ===
          sessionId,
      );
      const hasResult = sessionEvents.some(
        (event) => eventKind(event) === "ck.agent.interop_session.result",
      );
      if (hasResult) break;
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    await testInfo.attach("agent-handoff-audit-chain.json", {
      body: JSON.stringify(sessionEvents, null, 2),
      contentType: "application/json",
    });

    // 1. Ordering: start precedes status(working) precedes result(completed).
    const kinds = sessionEvents.map(eventKind);
    const startIdx = kinds.indexOf("ck.agent.interop_session.start");
    const statusIdx = kinds.indexOf("ck.agent.interop_session.status");
    const resultIdx = kinds.indexOf("ck.agent.interop_session.result");
    expect(startIdx, "start event present").toBeGreaterThanOrEqual(0);
    expect(statusIdx, "status event present").toBeGreaterThan(startIdx);
    expect(resultIdx, "result event present").toBeGreaterThan(statusIdx);
    // No status after the terminal result.
    expect(
      kinds.slice(resultIdx + 1),
      "no status event may follow the terminal result",
    ).not.toContain("ck.agent.interop_session.status");

    const statusEvent = sessionEvents[statusIdx];
    expect((statusEvent.payload as Record<string, unknown>).status).toBe(
      "working",
    );

    // 2. Result carries the Ed25519 audit_binding (spec §5.4 / soland
    //    REFERENCE_AGENT_AUDIT_ED25519 reference key).
    const resultEvent = sessionEvents[resultIdx];
    const resultPayload = resultEvent.payload as Record<string, unknown>;
    expect(resultPayload.status).toBe("completed");
    const binding = resultPayload.audit_binding as
      | Record<string, unknown>
      | undefined;
    expect(binding, "result must carry an audit_binding").toBeTruthy();
    expect(binding?.binding_kind).toBe("ed25519_v1");
    expect(binding?.actor_id).toBe(alice.did);
    expect(typeof binding?.signature).toBe("string");
    expect(typeof binding?.public_key_b64).toBe("string");
    expect(typeof binding?.canonical_subject).toBe("string");

    // 3. The canonical_subject is the spec-pinned shape that
    //    arkret_sdk::agent_binding::verify_audit_binding_by_kind recomputes:
    //    session_id / agent_principal_id / echo / actor_id / binding_kind.
    const subject = binding?.canonical_subject as string;
    expect(subject).toContain(`session_id=${sessionId}`);
    expect(subject).toContain(`actor_id=${alice.did}`);
    expect(subject.endsWith("binding_kind=ed25519_v1")).toBe(true);
  });

  test("Phase B — capability approval with allowed_endpoints / requires_human_approval gate", async ({
    browser,
    request,
  }) => {
    // spec: §4 (explicit + authorizable upgrade), §7 (capability actions +
    // constraint: allowed_endpoints / requires_human_approval), §8
    // (pre-start capability check). Drives the inkson /agents interop approval
    // modal: the human-approval gate MUST be acknowledged before the
    // controller can confirm, and the resulting `ck.capability.grant`
    // carries `actions=[ck.agent.interop_session.start]` with a single-valued
    // `allowed_endpoints` pinned to the runtime base URL.
    const stamp = Date.now();
    const remoteAgent = uniqueUser(`agent-handoff-remote-b-${stamp}`);
    const aliceFlow = await openDpopUserPage(
      browser,
      request,
      `agent-handoff-alice-b-${stamp}`,
      { prepareMlsDevice: false },
    );
    if (!aliceFlow) {
      assertJointStackNotRequired("agent approval browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    await ensureRegistered(request, remoteAgent);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `agent-approval-${stamp}`,
    });
    const allowedEndpoint = `${mockAgentRuntimeBaseUrl() ?? "https://agent.example"}/v1/a2a/tasks`;

    const alicePage = aliceFlow.page;
    try {
      // Select the realm in-UI so the panel authors the grant into it,
      // then open the agents panel.
      await alicePage.gotoTimelineRealm(realmId);
      await alicePage.page.goto("/agents", { waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("agents-panel")).toBeVisible({
        timeout: 120_000,
      });

      // Open the interop capability-approval modal.
      await alicePage.clickWithPassivePromptRetry(
        alicePage.page.getByTestId("agent-interop-approve-open-button"),
      );
      const modal = alicePage.page.getByTestId("agent-interop-publish-modal");
      await expect(modal).toBeVisible();
      await modal
        .getByTestId("agent-interop-target-input")
        .fill(remoteAgent.did);
      await modal
        .getByTestId("agent-interop-allowed-endpoint-input")
        .fill(allowedEndpoint);

      // The human-approval gate (spec §4) blocks confirm until acknowledged.
      const confirm = modal.getByTestId("agent-interop-publish-confirm-button");
      await expect(confirm).toBeDisabled();
      await modal
        .getByTestId("agent-interop-human-approval-ack-button")
        .click();
      await expect(confirm).toBeEnabled();
      await confirm.click();

      // The grant id surfaces once the ck.capability.grant lands.
      const grantIdNode = modal.getByTestId("agent-interop-grant-id");
      await expect(grantIdNode).toBeVisible({ timeout: 30_000 });
      const grantId = await grantIdNode.getAttribute("data-grant-id");
      expect(grantId, "authored grant id").toBeTruthy();
      await expect(
        alicePage.page.getByTestId("agent-interop-approval-state"),
      ).toHaveAttribute("data-state", "granted");

      // Assert the wire grant: actions include the start action, and
      // allowed_endpoints is a single-valued precise list (spec §7).
      const events = await request.get(
        `${solandBaseUrl()}/_arkret/self/events?realms=${encodeURIComponent(realmId)}&limit=100`,
        { headers: { authorization: `Bearer ${aliceToken}` } },
      );
      expect(events.status()).toBe(200);
      const body = await events.json();
      const list: Array<Record<string, unknown>> = body.events ?? [];
      const grantEvent = list.find((event) => {
        if (eventKind(event) !== "ck.capability.grant") {
          return false;
        }
        const payload = event.payload as Record<string, unknown> | undefined;
        const grant = payload?.grant as Record<string, unknown> | undefined;
        return grant?.id === grantId;
      });
      expect(grantEvent, "ck.capability.grant for the authored grant").toBeTruthy();
      const grant = (grantEvent!.payload as Record<string, unknown>)
        .grant as Record<string, unknown>;
      expect(grant.actions).toEqual(
        expect.arrayContaining(["ck.agent.interop_session.start"]),
      );
      expect(grant.subject).toBe(remoteAgent.did);
      const constraints = grant.constraints as Record<string, unknown>;
      expect(constraints.allowed_endpoints).toEqual([allowedEndpoint]);
      expect(constraints.requires_human_approval).toBe(true);
    } finally {
      await alicePage.close();
    }
  });

  test("Phase C — invocation handoff with status transcript (negotiating → accepted → working)", async ({
    browser,
    request,
  }) => {
    // spec: §5.2 (start), §5.3 (status enum + throttled transitions), §6
    // step 5-7. The in-process echo bridge only emits a single
    // status(working); to exercise the full standard transition set the
    // harness injects the intermediate `negotiating` / `accepted` status
    // events (a real streaming runtime would emit these). The inkson
    // /agents `agent-session-row` then renders the latest status, which the
    // test polls until it advances to `working`.
    const stamp = Date.now();
    const alice = uniqueUser(`agent-handoff-alice-c-${stamp}`);
    const remoteAgent = uniqueUser(`agent-handoff-remote-c-${stamp}`);
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, remoteAgent),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `agent-handoff-${stamp}`,
    });

    // Register the agent endpoint (no endpoint_url → in-process echo).
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.agent.endpoint",
        schemaId: "ck.schema.agent.v1",
        payload: {
          agent_id: remoteAgent.did,
          endpoints: [{ protocol: "a2a" }],
        },
      }),
      { context: "register endpoint for handoff" },
    );

    const sessionId = `ck:agent_interop_session:${uuidV7()}`;
    // Submit the start first: soland's interop-session writer policy only
    // authorizes status writes from the session's start actor, so the start
    // (authored by alice) MUST precede the injected status transcript.
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.agent.interop_session.start",
        schemaId: "ck.schema.agent.v1",
        payload: {
          session_id: sessionId,
          counterparty_agent: remoteAgent.did,
          protocol: "a2a",
          capability_grant: typedId("grant"),
          audit_mode: "summary_and_artifacts",
          params: { op: "synthesize", doc: "handoff-c" },
        },
      }),
      { context: "submit interop_session.start" },
    );
    // The in-process bridge fans out a single status(working); inject the
    // intermediate standard §5.3 transitions a streaming runtime would emit
    // (negotiating → accepted → working). All authored by the start actor.
    for (const status of ["negotiating", "accepted", "working"]) {
      await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ck.agent.interop_session.status",
          schemaId: "ck.schema.agent.v1",
          payload: { session_id: sessionId, status },
        }),
        { context: `inject status ${status}` },
      );
    }

    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
    });
    try {
      await alicePage.page.goto(`/chat/${realmId}`, {
        waitUntil: "domcontentloaded",
      });
      await alicePage.page.goto("/agents", { waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("agents-panel")).toBeVisible({
        timeout: 120_000,
      });

      // The agent-session-row for this session must render and advance to
      // `working` (the bridge's status(working) is the latest observed
      // status). The panel polls soland every 4s, so allow several ticks.
      const row = alicePage.page.locator(
        `[data-testid="agent-session-row"][data-session-id="${sessionId}"]`,
      );
      await expect(row).toBeVisible({ timeout: 60_000 });
      await expect(row).toHaveAttribute("data-status", "working", {
        timeout: 60_000,
      });
      // At least the three injected/bridge status updates were folded.
      const statusCount = await row.getAttribute("data-status-count");
      expect(Number(statusCount)).toBeGreaterThanOrEqual(3);
    } finally {
      await alicePage.close();
    }
  });

  test("Phase D — publish-to-source strand lands Strand with attribution", async ({
    browser,
    request,
  }) => {
    // spec: §5.4 (result_objects / artifacts / attribution), §6 step 8-9.
    // The inkson /agents publish modal authors a synthesis Strand whose
    // actor_id is the controller (alice) but whose `attribution` preserves
    // the executing agent. The signer toggle
    // `publish-modal-signer-self-with-attribution` selects that semantics.
    const stamp = Date.now();
    const alice = uniqueUser(`agent-handoff-alice-d-${stamp}`);
    const remoteAgent = uniqueUser(`agent-handoff-remote-d-${stamp}`);
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, remoteAgent),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `agent-publish-${stamp}`,
    });
    const resultRef = `ck:strand:${uuidV7()}`;
    const artifactRef = `ck:morph:${uuidV7()}`;

    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
    });
    try {
      await alicePage.page.goto(`/chat/${realmId}`, {
        waitUntil: "domcontentloaded",
      });
      await alicePage.page.goto("/agents", { waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("agents-panel")).toBeVisible({
        timeout: 120_000,
      });

      const publishSurface = alicePage.page.getByTestId(
        "agent-publish-to-source",
      );
      await publishSurface
        .getByTestId("agent-publish-attribution-input")
        .fill(remoteAgent.did);
      await publishSurface
        .getByTestId("agent-publish-result-ref-input")
        .fill(resultRef);
      await publishSurface
        .getByTestId("agent-publish-artifact-ref-input")
        .fill(artifactRef);
      await publishSurface.getByTestId("agent-publish-open-button").click();

      const modal = alicePage.page.getByTestId("publish-modal");
      await expect(modal).toBeVisible();
      // The self-with-attribution signer branch is selected by default.
      await expect(
        modal.getByTestId("publish-modal-signer-self-with-attribution"),
      ).toHaveAttribute("data-selected", "true");
      await modal.getByTestId("publish-modal-confirm").click();

      const strandIdNode = modal.getByTestId("agent-publish-strand-id");
      await expect(strandIdNode).toBeVisible({ timeout: 30_000 });
      const strandId = await strandIdNode.getAttribute("data-strand-id");
      expect(strandId, "published strand id").toBeTruthy();
      await expect(
        alicePage.page.getByTestId("agent-publish-state"),
      ).toHaveAttribute("data-state", "published");

      // Assert the published Strand: actor_id = alice, attribution =
      // remote agent, workflow_type contains synthesis (spec §5.4).
      const events = await request.get(
        `${solandBaseUrl()}/_arkret/self/events?realms=${encodeURIComponent(realmId)}&limit=100`,
        { headers: { authorization: `Bearer ${aliceToken}` } },
      );
      expect(events.status()).toBe(200);
      const body = await events.json();
      const list: Array<Record<string, unknown>> = body.events ?? [];
      const strandEvent = list.find((event) => {
        if (eventKind(event) !== "ck.strand.create") {
          return false;
        }
        const payload = event.payload as Record<string, unknown> | undefined;
        const object = payload?.object as Record<string, unknown> | undefined;
        return object?.id === strandId;
      });
      expect(strandEvent, "ck.strand.create for the published strand").toBeTruthy();
      expect(strandEvent!.actor_id).toBe(alice.did);
      const object = (strandEvent!.payload as Record<string, unknown>)
        .object as Record<string, unknown>;
      expect(object.attribution).toBe(remoteAgent.did);
      const metadata = object.metadata as Record<string, unknown>;
      const fields = metadata.fields as Record<string, unknown>;
      expect(String(fields.workflow_type)).toContain("synthesis");
    } finally {
      await alicePage.close();
    }
  });
});
