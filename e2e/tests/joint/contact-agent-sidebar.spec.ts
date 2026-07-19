import { expect, type APIRequestContext } from "@playwright/test";
import type { ContactListRow } from "../../helpers/contact-api";
import { solandBaseUrl } from "../../helpers/env";
import { test as jointTest } from "../../helpers/joint-fixture";
import {
  selfPathHeadersForDpopSession,
  type DpopUserSession,
} from "../../helpers/users";

jointTest.describe.configure({ mode: "serial" });

jointTest.describe("Contacts agent hierarchy @fully-implemented", () => {
  jointTest(
    "pins self first, hides never-effective own agents, and hides non-receiving contact agents",
    async ({ jointRealm, request }) => {
      jointTest.setTimeout(360_000);
      const stamp = Date.now();
      const slug = `contacts-${stamp.toString(36)}`;
      const alicePage = jointRealm.alicePage.page;
      await alicePage.goto("/settings/agents", { waitUntil: "domcontentloaded" });
      await expect(alicePage.getByTestId("agent-admin-list")).toBeVisible({
        timeout: 120_000,
      });
      await alicePage.getByTestId("agent-admin-create-open-button").click();
      await alicePage.getByTestId("agent-admin-provision-agent-slug").fill(slug);
      await alicePage.getByTestId("agent-admin-provision-button").click();
      await expect(alicePage.getByTestId("agent-admin-last-op")).toContainText(
        "Created",
        { timeout: 120_000 },
      );
      await expect(
        alicePage.getByTestId("agent-admin-row").filter({ hasText: slug }),
      ).toBeVisible();

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
        aliceSelfGroup
          .getByTestId("contact-sidebar-agent-row")
          .filter({ hasText: slug }),
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
