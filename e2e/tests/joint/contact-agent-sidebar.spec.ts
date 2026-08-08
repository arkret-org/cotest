import { expect, type APIRequestContext } from "@playwright/test";
import type { ContactListRow } from "../../helpers/contact-api";
import { solandBaseUrl } from "../../helpers/env";
import { test as jointTest } from "../../helpers/joint-fixture";
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
        (row) => row.peer === jointRealm.alice.did,
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
        jointRealm.alice.did,
      );
      await expect(aliceSelfGroup).toContainText("ME");

      // The Contacts sidebar is a chat surface: only agents that ever became
      // effective (active / paused) belong here. The freshly provisioned
      // agent is still not ready with runtime_key_missing, so it must stay out of the
      // sidebar and out of the Agents count pill until pairing completes;
      // it remains manageable in Settings → My Agents. Wait for Bob's
      // contact row first — contacts and own agents land from the same
      // sidebar load, so this guards against asserting before data arrives.
      await expect(
        alicePage.locator(
          `[data-testid="direct-conversation-row"][data-peer="${jointRealm.bob.did}"]`,
        ),
      ).toBeVisible({ timeout: 30_000 });
      await expect(
        aliceSelfGroup.locator(
          `[data-testid="contact-sidebar-agent-row"][data-agent="${pendingAgentId}"]`,
        ),
      ).toHaveCount(0);
      await expect(aliceSelfGroup).not.toContainText("Agents");

      const bobPage = jointRealm.bobPage.page;
      const allowedAgent = {
        agent_id: `did:web:agents.joint-e2e.local:${stamp}`,
        controller_id: jointRealm.alice.did,
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
            row.peer === jointRealm.alice.did
              ? { ...row, agents: [allowedAgent] }
              : row,
          );
          await route.fulfill({
            response: upstream,
            json: { ...body, contacts },
          });
        },
      );
      await bobPage.getByTestId("realm-sidebar-tab-direct").click();
      const bobGroups = bobPage.locator(".contact-sidebar-group");
      await expect(bobGroups.first()).toHaveAttribute(
        "data-testid",
        "contact-sidebar-self-group",
      );
      const aliceContact = bobPage.locator(
        `[data-testid="direct-conversation-row"][data-peer="${jointRealm.alice.did}"]`,
      );
      await expect(aliceContact).toBeVisible({ timeout: 30_000 });
      const aliceGroup = bobPage.locator(
        `.contact-sidebar-group[data-controller="${jointRealm.alice.did}"]`,
      );
      const toggle = aliceGroup.getByTestId("contact-sidebar-agent-toggle");
      await expect(toggle).toContainText("Agents 1");
      await toggle.click();
      const allowedAgentRow = aliceGroup
        .getByTestId("contact-sidebar-agent-row")
        .filter({ hasText: allowedAgent.display_name });
      await expect(allowedAgentRow).toBeVisible();
      await expect(allowedAgentRow).toHaveAttribute(
        "data-controller",
        jointRealm.alice.did,
      );
      await allowedAgentRow.click();
      await expect(bobPage).toHaveURL(/\/direct\/.*0000000000b1\/.*0000000000b2$/);
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
    const prepareResponsePromise = page.waitForResponse((response) => {
      const outgoing = response.request();
      return (
        outgoing.method() === "POST" &&
        new URL(outgoing.url()).pathname === "/_arkret/self/agents" &&
        (outgoing.postDataJSON() as { phase?: string }).phase === "prepare"
      );
    });
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
    const principalControlRealmId = requiredString(
      preparation,
      "principal_control_realm_id",
      "prepare outcome",
    );
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
    expect(agentId).toMatch(/^did:/);
    expect(principalControlRealmId).toMatch(/^ak:realm:/);
    expect(controllerRealmId).toMatch(/^ak:realm:/);
    expect(allocationHandle).toBeTruthy();
    expect(requestedScopeDigest).toMatch(/^sha256:[0-9a-f]{64}$/);

    const commit = await commitObserved;
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
    expect(provisionEvent.actor_id).toBe(controller.user.did);
    expect(provisionEvent.realm_id).toBe(controllerRealmId);
    expect(provisionEvent.proofs).not.toHaveLength(0);
    const provisionPayload = asJsonObject(
      provisionEvent.payload,
      "ak.agent.provision payload",
    );
    expect(provisionPayload.schema).toBe("ak.schema.agent_provision.v1");
    expect(provisionPayload.agent_id).toBe(agentId);
    expect(provisionPayload.controller_id).toBe(controller.user.did);
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
    expect(commitResponse.status(), commitText).toBe(201);
    const completed = asJsonObject(
      JSON.parse(commitText),
      "Agent provision complete outcome",
    );
    expect(completed.status).toBe("complete");
    expect(completed.agent_id).toBe(agentId);
    expect(completed.principal_control_realm_id).toBe(principalControlRealmId);
    expect(completed.requested_scope_digest).toBe(requestedScopeDigest);
    expect(completed.pairing_request_id).toBeTruthy();
    expect(completed.pairing_code).toBeTruthy();

    // Exact commit replay is protocol idempotency, independent of the HTTP
    // Idempotency-Key header and without minting a second pairing handle.
    const retry = await request.post(url, {
      headers: selfPathHeadersForDpopSession(controller, "POST", url),
      data: commit,
    });
    const retryText = await retry.text();
    expect(retry.status(), retryText).toBe(201);
    expect(JSON.parse(retryText)).toEqual(completed);
    await expect(page.getByTestId("agent-admin-pairing-card")).toBeVisible({
      timeout: 120_000,
    });
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
  const requestUrl = `${solandBaseUrl()}/_arkret/self/contacts/request`;
  const requested = await request.post(requestUrl, {
    headers: selfPathHeadersForDpopSession(requester, "POST", requestUrl),
    data: {
      target: responder.user.did,
      requested_scopes: ["direct_message"],
      introduction_evidence: { kind: "explicit_address" },
    },
  });
  const requestedText = await requested.text();
  expect(requested.status(), requestedText).toBe(201);
  const requestedBody = JSON.parse(requestedText) as {
    request_event_ref: string;
  };

  const respondUrl = `${solandBaseUrl()}/_arkret/self/contacts/respond`;
  const responded = await request.post(respondUrl, {
    headers: selfPathHeadersForDpopSession(responder, "POST", respondUrl),
    data: {
      request_id: requestedBody.request_event_ref,
      requester: requester.user.did,
      action: "accept",
      granted_scopes: ["direct_message"],
    },
  });
  const respondedText = await responded.text();
  expect(responded.status(), respondedText).toBe(200);
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
