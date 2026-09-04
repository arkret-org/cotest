import { expect, type APIRequestContext } from "../../helpers/arkret-test";
import {
  requestContactArkret,
  respondContactArkret,
  type ContactListRow,
} from "../../helpers/contact-api";
import { solandBaseUrl } from "../../helpers/env";
import { test as jointTest } from "../../helpers/joint-fixture";
import { accountActorId, canonicalJson } from "../../helpers/soland-api";
import {
  selfPathHeadersForDpopSession,
  type DpopUserSession,
  type JointUserPage,
} from "../../helpers/users";

jointTest.describe.configure({ mode: "serial" });

jointTest.describe("Contacts agent hierarchy @fully-implemented", () => {
  jointTest(
    "pins self first, hides never-effective own agents, and hides non-receiving contact agents",
    async ({ jointRealm, request }) => {
      jointTest.setTimeout(360_000);
      const stamp = Date.now();
      const slug = `contacts-${stamp.toString(36)}`;
      await jointRealm.bobPage.completeRecoveryKeySetupIfPrompted(30_000);
      const pendingAgentId = await provisionPendingAgent(
        request,
        jointRealm.aliceSession,
        jointRealm.alicePage,
        slug,
      );
      await establishDirectMessageContact(
        request,
        jointRealm.aliceSession,
        jointRealm.bobSession,
      );
      const realBobContacts = await listContacts(
        request,
        jointRealm.bobSession,
      );
      const realAliceRow = realBobContacts.find(
        (row) => row.peer === jointRealm.alice.id,
      );
      expect(realAliceRow?.agents ?? []).toHaveLength(0);

      const alicePage = jointRealm.alicePage.page;
      await alicePage.getByTestId("realm-sidebar-tab-direct").click();

      const aliceGroups = alicePage.locator(".contact-sidebar-group");
      const aliceSelfGroup = alicePage.getByTestId("contact-sidebar-self-group");
      await expect(aliceGroups.first()).toHaveAttribute(
        "data-testid",
        "contact-sidebar-self-group",
      );
      await expect(aliceSelfGroup.getByTestId("contact-sidebar-self-row")).toHaveAttribute(
        "data-peer",
        jointRealm.alice.id,
      );
      await expect(aliceSelfGroup).toContainText("ME");

      // The Contacts sidebar is a chat surface: only agents that ever became
      // effective (active / paused) belong here. The freshly provisioned
      // agent is still not ready with runtime_key_missing, so it must stay out of the
      // sidebar and out of the Agents count pill until pairing completes;
      // it remains manageable in Settings → My Agents. Wait for Bob's
      // contact row first — contacts and own agents land from the same
      // sidebar load, so this guards against asserting before data arrives.
      const bobContact = alicePage.getByTestId("direct-conversation-row").first();
      await expect(bobContact).toBeVisible({ timeout: 30_000 });
      await expect(bobContact).toHaveAttribute(
        "data-peer",
        canonicalJson(accountActorId(jointRealm.bob.id)),
      );
      await expect(
        aliceSelfGroup.locator(
          `[data-testid="contact-sidebar-agent-row"][data-agent="${pendingAgentId}"]`,
        ),
      ).toHaveCount(0);
      await expect(aliceSelfGroup).not.toContainText("Agents");

      const bobPage = jointRealm.bobPage.page;
      const allowedAgent = {
        agent_id: `ak:did_core:web:agents.joint-e2e.local:${stamp}`,
        controller_account_id: jointRealm.aliceSession.accountId,
        display_name: `Alice Allowed Agent ${stamp}`,
        agent_slug: `allowed-${stamp.toString(36)}`,
        direct_conversation: {
          realm_id: "ak:realm:AdrCf1FpSdW2-osrupL1Va1DkS3PNlzZsPum0wyLnQwz",
          main_strand_id: "ak:strand:AQAG6N7vDa1nxssksTCIdqNm-FTDJoKuBrHIclJ7FBy0",
          binding_event_ref: "ak:event:ARn7D_ihLMur4IPmD8Tz75ZThvC26r14I60hC2_uRS8q",
          state: "active",
        },
      };
      // The live API assertion above owns the permission/filtering contract.
      // This one-response overlay isolates Inkson's positive nested-row and
      // navigation behavior without fabricating server state in a database.
      await bobPage.route(
        ({ pathname }) => pathname === "/_arkret/self/contacts",
        async (route) => {
          if (route.request().method() !== "GET") {
            await route.continue();
            return;
          }
          const upstream = await route.fetch();
          const body = (await upstream.json()) as {
            contacts?: Array<Record<string, unknown>>;
          };
          const contacts = (body.contacts ?? []).map((row) =>
            row.peer === jointRealm.alice.id
              ? { ...row, agents: [allowedAgent] }
              : row,
          );
          await route.fulfill({
            response: upstream,
            json: { ...body, contacts },
          });
        },
      );
      await bobPage.reload();
      await bobPage.getByTestId("realm-sidebar-tab-direct").click();
      const bobGroups = bobPage.locator(".contact-sidebar-group");
      await expect(bobGroups.first()).toHaveAttribute(
        "data-testid",
        "contact-sidebar-self-group",
      );
      const aliceContact = bobPage.getByTestId("direct-conversation-row").first();
      await expect(aliceContact).toBeVisible({ timeout: 30_000 });
      await expect(aliceContact).toHaveAttribute(
        "data-peer",
        canonicalJson(accountActorId(jointRealm.alice.id)),
      );
      const aliceGroup = bobPage
        .locator(".contact-sidebar-group")
        .filter({ has: aliceContact });
      const toggle = aliceGroup.getByTestId("contact-sidebar-agent-toggle");
      await expect(toggle).toContainText("Agents 1");
      await toggle.click();
      const allowedAgentRow = aliceGroup
        .getByTestId("contact-sidebar-agent-row")
        .filter({ hasText: allowedAgent.display_name });
      await expect(allowedAgentRow).toBeVisible();
      await expect(allowedAgentRow).toHaveAttribute(
        "data-controller",
        jointRealm.alice.id,
      );
      await allowedAgentRow.click();
      await expect
        .poll(() => new URL(bobPage.url()).pathname)
        .toBe(
          `/direct/${allowedAgent.direct_conversation.realm_id}/${allowedAgent.direct_conversation.main_strand_id}`,
        );
    },
  );
});

function asJsonObject(value: unknown, where: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${where} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function requiredString(
  object: Record<string, unknown>,
  field: string,
  where: string,
): string {
  const value = object[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${where}.${field} must be a non-empty string`);
  }
  return value;
}

async function provisionPendingAgent(
  request: APIRequestContext,
  controller: DpopUserSession,
  controllerPage: JointUserPage,
  agentSlug: string,
): Promise<string> {
  const url = `${solandBaseUrl()}/_arkret/self/agents`;
  const page = controllerPage.page;
  await controllerPage.gotoSettings();
  await page.getByTestId("settings-nav-item-agents").click();
  await expect(page).toHaveURL(/\/settings\/agents(?:\?|$)/);
  await page.getByTestId("agent-admin-create-open-button").click();
  await expect(page.getByTestId("agent-admin-provision")).toBeVisible();
  await page.getByTestId("agent-admin-provision-agent-slug").fill(agentSlug);
  await expect(page.getByTestId("agent-admin-provision-button")).toBeEnabled();

  let releaseCommit = () => {};
  const commitGate = new Promise<void>((resolve) => {
    releaseCommit = resolve;
  });
  let observeCommit = (_body: Record<string, unknown>) => {};
  const commitObserved = new Promise<Record<string, unknown>>((resolve) => {
    observeCommit = resolve;
  });
  const holdCommit = async (route: Parameters<Parameters<typeof page.route>[1]>[0]) => {
    const intercepted = route.request();
    if (intercepted.method() === "POST") {
      const body = asJsonObject(intercepted.postDataJSON(), "provision request");
      if (body.phase === "commit") {
        observeCommit(body);
        await commitGate;
      }
    }
    await route.continue();
  };
  await page.route("**/_arkret/self/agents", holdCommit);

  try {
    const prepareResponsePromise = page.waitForResponse(
      (response) => {
        const outgoing = response.request();
        return (
          outgoing.method() === "POST" &&
          new URL(outgoing.url()).pathname === "/_arkret/self/agents" &&
          (outgoing.postDataJSON() as { phase?: string }).phase === "prepare"
        );
      },
      { timeout: 90_000 },
    );
    await page.getByTestId("agent-admin-provision-button").click();
    const prepareResponse = await prepareResponsePromise;
    const prepareText = await prepareResponse.text();
    expect(prepareResponse.status(), prepareText).toBe(200);
    const preparation = asJsonObject(
      JSON.parse(prepareText),
      "Agent provision prepare outcome",
    );
    expect(preparation.status).toBe("awaiting_controller_event");
    const agentId = requiredString(preparation, "agent_id", "prepare outcome");
    // The prepare phase is allocation-only.  The controller derives the Agent
    // PCR id from its locally frozen genesis Event and first discloses it in
    // the commit; the Station must not allocate or predict it here.
    expect(preparation).not.toHaveProperty("principal_control_realm_id");
    const controllerRealmId = requiredString(
      preparation,
      "controller_realm_id",
      "prepare outcome",
    );
    const allocationHandle = requiredString(
      preparation,
      "allocation_handle",
      "prepare outcome",
    );
    const requestedScopeDigest = requiredString(
      preparation,
      "requested_scope_digest",
      "prepare outcome",
    );
    expect(agentId).toMatch(/^ak:did_core:/);
    expect(controllerRealmId).toMatch(/^ak:realm:/);
    expect(allocationHandle).toBeTruthy();
    expect(requestedScopeDigest).toMatch(/^sha256:[0-9a-f]{64}$/);

    const commit = await commitObserved;
    const principalControlRealmId = requiredString(
      commit,
      "principal_control_realm_id",
      "Agent provision commit",
    );
    expect(principalControlRealmId).toMatch(/^ak:realm:/);
    expect(commit.agent_id).toBe(agentId);
    expect(commit.principal_control_realm_id).toBe(principalControlRealmId);
    expect(commit.allocation_handle).toBe(allocationHandle);
    expect(typeof commit.operation_id).toBe("string");
    expect(typeof commit.idempotency_key).toBe("string");
    expect(commit.slug).toBe(agentSlug);
    const provisionSubmission = asJsonObject(
      commit.provision_event,
      "Agent provision commit.provision_event",
    );
    const provisionEvent = asJsonObject(
      provisionSubmission.event,
      "Agent provision EventInitialSubmission.event",
    );
    expect(provisionEvent.kind).toBe("ak.agent.provision");
    expect(provisionEvent.actor_id).toEqual(accountActorId(controller.user.id));
    expect(provisionEvent.realm_id).toBe(controllerRealmId);
    expect(provisionEvent.proofs).not.toHaveLength(0);
    const provisionPayload = asJsonObject(
      provisionEvent.payload,
      "ak.agent.provision payload",
    );
    expect(provisionPayload.schema).toBe("ak.schema.agent_provision.v1");
    expect(provisionPayload.agent_id).toBe(agentId);
    expect(provisionPayload.controller_principal_id).toBe(controller.user.id);
    expect(provisionPayload.principal_control_realm_id).toBe(
      principalControlRealmId,
    );
    expect(provisionPayload.agent_slug).toBe(agentSlug);
    expect(provisionPayload.requested_scope_digest).toBe(requestedScopeDigest);

    // prepare is allocation-only: before commit is released, the Agent MUST
    // not exist in the durable self projection and no pairing handle exists.
    const beforeCommit = await request.get(url, {
      headers: selfPathHeadersForDpopSession(controller, "GET", url),
    });
    const beforeCommitText = await beforeCommit.text();
    expect(beforeCommit.status(), beforeCommitText).toBe(200);
    const beforeCommitBody = asJsonObject(
      JSON.parse(beforeCommitText),
      "Agent list before provision commit",
    );
    const beforeCommitAgents = Array.isArray(beforeCommitBody.agents)
      ? beforeCommitBody.agents
      : [];
    expect(
      beforeCommitAgents.some((agent) => {
        const candidate = asJsonObject(agent, "Agent list entry");
        return candidate.agent_id === agentId;
      }),
    ).toBeFalsy();

    const commitResponsePromise = page.waitForResponse((response) => {
      const outgoing = response.request();
      return (
        outgoing.method() === "POST" &&
        new URL(outgoing.url()).pathname === "/_arkret/self/agents" &&
        asJsonObject(outgoing.postDataJSON(), "Agent provision request").phase ===
          "commit"
      );
    });
    releaseCommit();
    const commitResponse = await commitResponsePromise;
    const commitText = await commitResponse.text();
    expect(commitResponse.status(), commitText).toBe(200);
    const awaitingPcrGenesis = asJsonObject(
      JSON.parse(commitText),
      "Agent provision awaiting-PCR-genesis outcome",
    );
    expect(awaitingPcrGenesis.status).toBe("awaiting_pcr_genesis");
    expect(awaitingPcrGenesis.agent_id).toBe(agentId);
    expect(awaitingPcrGenesis.principal_control_realm_id).toBe(
      principalControlRealmId,
    );
    expect(awaitingPcrGenesis.requested_scope_digest).toBe(
      requestedScopeDigest,
    );

    // The client now submits and seals the separately frozen Agent PCR
    // genesis, publishes the DID binding entry, and only then exposes pairing.
    await expect(page.getByTestId("agent-admin-pairing-card")).toBeVisible({
      timeout: 120_000,
    });

    // Exact commit replay after those external acceptance steps returns the
    // first terminal materialization without minting another pairing handle.
    const retry = await request.post(url, {
      headers: selfPathHeadersForDpopSession(controller, "POST", url),
      data: commit,
    });
    const retryText = await retry.text();
    expect(retry.status(), retryText).toBe(201);
    const completed = asJsonObject(
      JSON.parse(retryText),
      "Agent provision complete outcome",
    );
    expect(completed.status).toBe("complete");
    expect(completed.agent_id).toBe(agentId);
    expect(completed.principal_control_realm_id).toBe(principalControlRealmId);
    expect(completed.requested_scope_digest).toBe(requestedScopeDigest);
    expect(completed.pairing_request_id).toBeTruthy();
    expect(completed.pairing_code).toBeTruthy();
    return requiredString(completed, "agent_id", "complete outcome");
  } finally {
    releaseCommit();
    await page.unroute("**/_arkret/self/agents", holdCommit);
  }
}

async function establishDirectMessageContact(
  request: APIRequestContext,
  requester: DpopUserSession,
  responder: DpopUserSession,
): Promise<void> {
  const { outcome } = await requestContactArkret(
    request,
    requester.grantJwt,
    responder.user.id,
    { requestedScopes: ["direct_message"] },
  );
  const responded = await respondContactArkret(
    request,
    responder.grantJwt,
    {
      requestId: outcome.request_event_ref,
      requesterId: requester.user.id,
      action: "accept",
      grantedScopes: ["direct_message"],
    },
  );
  expect(responded.state).toBe("accepted");
}

async function listContacts(
  request: APIRequestContext,
  session: DpopUserSession,
): Promise<ContactListRow[]> {
  const url = `${solandBaseUrl()}/_arkret/self/contacts`;
  const response = await request.get(url, {
    headers: selfPathHeadersForDpopSession(session, "GET", url),
  });
  const text = await response.text();
  expect(response.status(), text).toBe(200);
  const body = JSON.parse(text) as { contacts?: ContactListRow[] };
  return body.contacts ?? [];
}
