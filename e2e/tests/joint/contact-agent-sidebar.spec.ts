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
      // agent is still pending_runtime_key, so it must stay out of the
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
          realm_id: "ak:realm:01964137-0000-7000-8000-0000000000b1",
          main_strand_id: "ak:strand:01964137-0000-7000-8000-0000000000b2",
          binding_event_ref: "ak:event:01964137-0000-7000-8000-0000000000b3",
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

type AgentProvisionPreparation = {
  status: "awaiting_controller_events";
  agent_id: string;
  principal_control_realm_id: string;
  controller_realm_id: string;
  requested_scope_digest: string;
};

type AgentProvisionEvent = {
  event_id: string;
  kind: string;
  actor_id: string;
  realm_id: string;
  payload: Record<string, unknown> & { source_refs?: string[] };
  proofs?: unknown[];
};

type AgentProvisionCommit = {
  phase: "commit";
  agent_id: string;
  principal_control_realm_id: string;
  slug: string;
  requested_scope: Record<string, unknown>;
  provision_events: {
    accountability_grant: AgentProvisionEvent;
    selector_claim: AgentProvisionEvent;
  };
};

type AgentProvisionComplete = {
  status: "complete";
  agent_id: string;
  principal_control_realm_id: string;
  requested_scope_digest: string;
  pairing_request_id: string;
  pairing_code: string;
  expires_at: string;
};

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
  let observeCommit = (_body: AgentProvisionCommit) => {};
  const commitObserved = new Promise<AgentProvisionCommit>((resolve) => {
    observeCommit = resolve;
  });
  const holdCommit = async (route: Parameters<Parameters<typeof page.route>[1]>[0]) => {
    const intercepted = route.request();
    if (intercepted.method() === "POST") {
      const body = intercepted.postDataJSON() as { phase?: string };
      if (body.phase === "commit") {
        observeCommit(body as AgentProvisionCommit);
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
    const preparation = JSON.parse(prepareText) as AgentProvisionPreparation;
    expect(preparation.status).toBe("awaiting_controller_events");
    expect(preparation.agent_id).toMatch(/^did:/);
    expect(preparation.principal_control_realm_id).toMatch(/^ak:realm:/);
    expect(preparation.controller_realm_id).toMatch(/^ak:realm:/);
    expect(preparation.requested_scope_digest).toMatch(/^sha256:[0-9a-f]{64}$/);

    const commit = await commitObserved;
    expect(commit.agent_id).toBe(preparation.agent_id);
    expect(commit.principal_control_realm_id).toBe(
      preparation.principal_control_realm_id,
    );
    expect(commit.slug).toBe(agentSlug);
    const accountability = commit.provision_events.accountability_grant;
    const selector = commit.provision_events.selector_claim;
    expect(accountability.kind).toBe("ak.identity.accountability_grant");
    expect(selector.kind).toBe("ak.agent.selector_claim");
    for (const event of [accountability, selector]) {
      expect(event.actor_id).toBe(controller.user.did);
      expect(event.realm_id).toBe(preparation.controller_realm_id);
      expect(event.proofs).not.toHaveLength(0);
    }
    expect(selector.payload.source_refs).toContain(accountability.event_id);

    // prepare is allocation-only: before commit is released, the Agent MUST
    // not exist in the durable self projection and no pairing handle exists.
    const beforeCommit = await request.get(url, {
      headers: selfPathHeadersForDpopSession(controller, "GET", url),
    });
    const beforeCommitText = await beforeCommit.text();
    expect(beforeCommit.status(), beforeCommitText).toBe(200);
    const beforeCommitBody = JSON.parse(beforeCommitText) as {
      agents?: Array<{ agent_id?: string }>;
    };
    expect(
      (beforeCommitBody.agents ?? []).some(
        (agent) => agent.agent_id === preparation.agent_id,
      ),
    ).toBeFalsy();

    const commitResponsePromise = page.waitForResponse((response) => {
      const outgoing = response.request();
      return (
        outgoing.method() === "POST" &&
        new URL(outgoing.url()).pathname === "/_arkret/self/agents" &&
        (outgoing.postDataJSON() as { phase?: string }).phase === "commit"
      );
    });
    releaseCommit();
    const commitResponse = await commitResponsePromise;
    const commitText = await commitResponse.text();
    expect(commitResponse.status(), commitText).toBe(201);
    const completed = JSON.parse(commitText) as AgentProvisionComplete;
    expect(completed.status).toBe("complete");
    expect(completed.agent_id).toBe(preparation.agent_id);
    expect(completed.principal_control_realm_id).toBe(
      preparation.principal_control_realm_id,
    );
    expect(completed.requested_scope_digest).toBe(
      preparation.requested_scope_digest,
    );
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
    return completed.agent_id;
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
