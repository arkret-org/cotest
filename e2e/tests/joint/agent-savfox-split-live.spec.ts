import { expect, type APIRequestContext, type Page, type Route } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { test as jointTest } from "../../helpers/joint-fixture";

// Mirrors inkson `APPROVAL_FALLBACK_POLL_INTERVAL`
// (src/components/agent_runtime_approval_prompt.rs). The prompt has exactly two
// discovery paths: the notification projection (wakeup) and this periodic
// poll. The scenario proves each one by disabling the other.
const APPROVAL_FALLBACK_POLL_MS = 30_000;
const AGENT_LIST_PATH = "/_arkret/self/agents";
const AGENT_LIST_GLOB = "**/_arkret/self/agents";
const ACCOUNT_SUBSCRIBE_PATH = "/_arkret/self/account/subscribe";
const RUNTIME_KEY_REQUEST_STATUS_PATH =
  "/_arkret/open/agent-pairing/runtime-key-requests/status";
const DIRECT_CONVERSATIONS_RESOLVE_PATH =
  "/_arkret/self/direct-conversations/resolve";
const KEYPACKAGES_CLAIM_PATH = "/_arkret/self/keys/keypackages/claim";
const EVENTS_SUBMIT_PATH = "/_arkret/self/events";
const MLS_TRANSACTION_KINDS = ["ak.mls.commit", "ak.mls.welcome"];

const isAccountSubscribe = ({ pathname }: URL) =>
  pathname === ACCOUNT_SUBSCRIBE_PATH;
const isEventsSubmit = ({ pathname }: URL) => pathname === EVENTS_SUBMIT_PATH;

type PairingHandle = {
  agentId: string;
  pairingRequestId: string;
  pairingCode: string;
};

type RuntimeKeyRequestStatus = {
  ok: boolean;
  status: string;
  runtime_state: string;
  approval_request_id?: string | null;
  authorized_event_ref?: string | null;
  authorized_verification_method?: string | null;
  authorized_public_key_digest?: string | null;
};

type DirectConversationBinding = {
  realm_id: string;
  main_strand_id: string;
  binding_event_ref: string;
};

// One joint chain, not a set of independent unit tests: a single Agent goes
// through provisioning, its first runtime pairing, a replacement pairing while
// the previous runtime is still active, Direct Conversation materialization
// with a crash in the middle, and finally a real user message answered by the
// live runtime. Every later phase consumes state produced by the earlier ones.
jointTest.describe.configure({ mode: "serial" });

jointTest.describe("Agent Savfox split live @fully-implemented", () => {
  jointTest(
    "pairs, replaces the runtime key, resumes a crashed direct conversation, and answers a real message",
    async ({ browser, jointRealm, request }) => {
      jointTest.setTimeout(1_200_000);

      // The joint harness does not provision the out-of-tree savfox gateway,
      // so this live pairing scenario only runs when both endpoints are
      // supplied externally. Follow the repo convention (README test tiers:
      // "a missing prerequisite must be an explicit test.skip with a
      // machine-readable reason") and skip instead of hard-throwing, which
      // otherwise reds the smoke/full gate on every run.
      const savfoxBaseUrlRaw = process.env.COTEST_SAVFOX_BASE_URL?.trim();
      const savfoxTokenRaw = process.env.COTEST_SAVFOX_TOKEN?.trim();
      jointTest.skip(
        !savfoxBaseUrlRaw || !savfoxTokenRaw,
        "PRECONDITION_SAVFOX_UNAVAILABLE: COTEST_SAVFOX_BASE_URL / COTEST_SAVFOX_TOKEN unset (harness does not provision the savfox gateway)",
      );
      const savfoxBaseUrl = savfoxBaseUrlRaw!.replace(/\/$/, "");
      const savfoxToken = savfoxTokenRaw!;
      const inkson = jointRealm.alicePage.page;
      const approvalModal = inkson.getByTestId("agent-runtime-approval-modal");
      const agentSlug = `savfox-live-${Date.now().toString(36)}`;

      // ── Phase 1: provision the Agent and capture its first pairing handle ──
      await jointRealm.alicePage.gotoSettings();
      await inkson.getByTestId("settings-nav-item-agents").click();
      await expect(inkson).toHaveURL(/\/settings\/agents(?:\?|$)/);
      await inkson.getByTestId("agent-admin-create-open-button").click();
      await inkson
        .getByTestId("agent-admin-provision-agent-slug")
        .fill(agentSlug);
      await expect(
        inkson.getByTestId("agent-admin-provision-button"),
      ).toBeEnabled();
      const commitResponsePromise = inkson.waitForResponse((response) => {
        const outgoing = response.request();
        return (
          outgoing.method() === "POST" &&
          new URL(outgoing.url()).pathname === AGENT_LIST_PATH &&
          (outgoing.postDataJSON() as { phase?: string }).phase === "commit"
        );
      });
      await inkson.getByTestId("agent-admin-provision-button").click();
      const commitResponse = await commitResponsePromise;
      const commitText = await commitResponse.text();
      expect(commitResponse.status(), commitText).toBe(201);
      const provisioned = JSON.parse(commitText) as {
        agent_id: string;
        pairing_request_id: string;
        pairing_code: string;
      };
      const firstPairing: PairingHandle = {
        agentId: provisioned.agent_id,
        pairingRequestId: provisioned.pairing_request_id,
        pairingCode: provisioned.pairing_code,
      };
      await expect(inkson.getByTestId("agent-admin-pairing-card")).toBeVisible({
        timeout: 180_000,
      });
      const pairingLink = await inkson
        .getByTestId("agent-admin-pairing-url")
        .inputValue();
      expect(pairingLink).toContain(
        "/_arkret/open/agent-pairing/resolve#token=",
      );

      // No runtime has submitted anything yet: the handle is open and carries
      // neither an approval request nor an authorized binding.
      const beforeRequest = await runtimeKeyRequestStatus(request, firstPairing);
      expect(beforeRequest.status).toBe("active");
      expect(beforeRequest.runtime_state).toBe("pending_runtime_key");
      expect(beforeRequest.approval_request_id ?? null).toBeNull();
      expect(beforeRequest.authorized_event_ref ?? null).toBeNull();

      const savfoxContext = await browser.newContext();
      const savfox = await savfoxContext.newPage();
      try {
        await openSavfoxArkretChannel(savfox, savfoxBaseUrl, savfoxToken);

        // ── Phase 2: the notification wakeup alone must raise the prompt ──
        // The periodic fallback poll is the only other discovery path and its
        // sole entry point is the agent list query. Keep that query failing for
        // the whole window: whether or not a poll tick lands inside it, the
        // fallback cannot discover the request, so a prompt that appears here
        // can only have come from the notification projection.
        const listOutage = await failAgentListQuery(inkson);
        try {
          await startSavfoxPairing(savfox, pairingLink);
          await expect(approvalModal).toBeVisible({ timeout: 120_000 });
        } finally {
          await listOutage.restore();
        }

        const inksonCode = (
          await inkson.getByTestId("agent-runtime-approval-code").innerText()
        ).trim();
        expect(inksonCode).toBe(firstPairing.pairingCode);
        const groupedPairingCode = `${inksonCode.slice(0, 4)} ${inksonCode.slice(4)}`;
        await expect(
          savfox.getByText(groupedPairingCode, { exact: true }),
        ).toBeVisible();
        await expect(
          savfox.getByText(
            `Waiting for Inkson approval... Compare pairing code ${inksonCode} with the Inkson prompt.`,
          ),
        ).toBeVisible({ timeout: 30_000 });

        // ── Phase 3: approve and record the first authorized binding ──
        await inkson.getByTestId("agent-runtime-approval-approve").click();
        await expect(approvalModal).toHaveCount(0, { timeout: 180_000 });
        await expect(
          savfox.getByText("Agent paired and channel saved.", { exact: true }),
        ).toBeVisible({ timeout: 180_000 });
        await saveSavfoxChannel(savfox);
        const arkretCard = savfox
          .locator(".channels-card")
          .filter({ hasText: "Arkret" });
        await expect(arkretCard).toHaveCount(1);
        await expect(arkretCard).toContainText(/Pairing\s*Paired/, {
          timeout: 120_000,
        });
        await expect
          .poll(
            async () => {
              await savfox.reload();
              await expect(arkretCard).toHaveCount(1);
              return (await arkretCard.textContent()) ?? "";
            },
            {
              timeout: 120_000,
              intervals: [1_000, 2_000, 5_000],
              message: "Savfox should surface the live Arkret session",
            },
          )
          .toContain("Listening");

        const firstBinding = await runtimeKeyRequestStatus(
          request,
          firstPairing,
        );
        expect(firstBinding.status).toBe("active");
        expect(firstBinding.runtime_state).toBe("ready");
        expect(firstBinding.approval_request_id ?? null).toBeNull();
        const firstAuthorizedEventRef = firstBinding.authorized_event_ref ?? "";
        expect(firstAuthorizedEventRef).not.toBe("");

        await inkson.reload();
        await expect(inkson.getByTestId("personal-agent-admin")).toBeVisible({
          timeout: 120_000,
        });
        await expect(approvalModal).toHaveCount(0);
        await expect(
          inkson.getByTestId("agent-admin-pairing-card"),
        ).toHaveCount(0);

        // ── Phase 4: a replacement pairing must not inherit the live binding ──
        // The previous runtime key stays active until the replacement pairing
        // completes, so the open handle projects `replacing`. A status poll for
        // the NEW pairing_request_id MUST NOT hand the new runtime the binding
        // the controller approved for the previous request.
        await inkson.getByTestId("agent-admin-row").first().click();
        await expect(
          inkson.getByTestId("agent-admin-runtime-state-badge"),
        ).toBeVisible({ timeout: 120_000 });
        const renewResponsePromise = inkson.waitForResponse((response) => {
          const outgoing = response.request();
          return (
            outgoing.method() === "POST" &&
            new URL(outgoing.url()).pathname.endsWith("/renew-pairing")
          );
        });
        await inkson.getByTestId("agent-admin-replace-runtime-button").click();
        await inkson
          .getByTestId("agent-admin-replace-runtime-confirm-button")
          .click();
        const renewResponse = await renewResponsePromise;
        const renewText = await renewResponse.text();
        expect(renewResponse.status(), renewText).toBe(200);
        const renewed = JSON.parse(renewText) as {
          agent_id: string;
          pairing_request_id: string;
          pairing_code?: string;
        };
        expect(renewed.agent_id).toBe(firstPairing.agentId);
        expect(renewed.pairing_request_id).not.toBe(
          firstPairing.pairingRequestId,
        );
        expect(renewed.pairing_code).toBeTruthy();
        const replacementPairing: PairingHandle = {
          agentId: firstPairing.agentId,
          pairingRequestId: renewed.pairing_request_id,
          pairingCode: renewed.pairing_code!,
        };

        const replacementBeforeRequest = await runtimeKeyRequestStatus(
          request,
          replacementPairing,
        );
        expect(replacementBeforeRequest.status).toBe("active");
        expect(replacementBeforeRequest.runtime_state).toBe("replacing");
        expect(replacementBeforeRequest.approval_request_id ?? null).toBeNull();
        expect(
          replacementBeforeRequest.authorized_event_ref ?? null,
          "a fresh replacement request must not resolve to the previous binding",
        ).toBeNull();
        expect(
          replacementBeforeRequest.authorized_verification_method ?? null,
        ).toBeNull();
        expect(
          replacementBeforeRequest.authorized_public_key_digest ?? null,
        ).toBeNull();

        await expect(
          inkson.getByTestId("agent-admin-pairing-card"),
        ).toBeVisible({ timeout: 120_000 });
        const replacementLink = await inkson
          .getByTestId("agent-admin-pairing-url")
          .inputValue();
        expect(replacementLink).not.toBe(pairingLink);

        // ── Phase 5: with the wakeup channel dead, the fallback poll recovers ──
        // Drop the account stream that carries notification deltas. The
        // notification projection can no longer learn about the request, so the
        // prompt can only be raised by the periodic fallback poll.
        const streamOutage = await dropAccountSubscribeStream(inkson);
        try {
          await openSavfoxArkretChannel(savfox, savfoxBaseUrl, savfoxToken);
          await startSavfoxPairing(savfox, replacementLink);
          await expect(approvalModal).toBeVisible({
            timeout: 3 * APPROVAL_FALLBACK_POLL_MS,
          });
        } finally {
          await streamOutage.restore();
        }
        expect(
          streamOutage.blockedCount(),
          "the notification wakeup channel must have been down while the prompt appeared",
        ).toBeGreaterThan(0);
        await expect(approvalModal).toContainText("replaces a runtime key");
        expect(
          (
            await inkson.getByTestId("agent-runtime-approval-code").innerText()
          ).trim(),
        ).toBe(replacementPairing.pairingCode);

        // ── Phase 6: approving the replacement supersedes the old binding ──
        await inkson.getByTestId("agent-runtime-approval-approve").click();
        await expect(approvalModal).toHaveCount(0, { timeout: 180_000 });
        await expect(
          savfox.getByText("Agent paired and channel saved.", { exact: true }),
        ).toBeVisible({ timeout: 180_000 });
        await saveSavfoxChannel(savfox);
        const replacementBinding = await runtimeKeyRequestStatus(
          request,
          replacementPairing,
        );
        expect(replacementBinding.runtime_state).toBe("ready");
        expect(replacementBinding.authorized_event_ref ?? "").not.toBe("");
        expect(
          replacementBinding.authorized_event_ref,
          "the replacement must authorize its own Event, not replay the previous one",
        ).not.toBe(firstAuthorizedEventRef);

        // ── Phase 7: Direct Conversation materialization survives a crash ──
        // Cut the signed MLS Commit / Welcome submission exactly once, reload
        // the client, and let it resume. `contact-and-direct-conversation.md`
        // requires the resumed run to replay the SAME Commit and Welcome
        // instead of authoring a second one, and it must not claim a second
        // peer KeyPackage.
        await inkson.reload();
        await expect(inkson.getByTestId("personal-agent-admin")).toBeVisible({
          timeout: 120_000,
        });
        const mlsSubmissions = trackMlsSubmissions(inkson);
        const keyPackageClaims = countRequests(inkson, KEYPACKAGES_CLAIM_PATH);
        const bindings = trackDirectConversationBindings(inkson);
        const crash = await cutFirstMlsTransactionSubmission(inkson);

        await openOwnAgentDirectChat(inkson, agentSlug);
        const crashedEventIds = await crash.waitForCutSubmission();
        expect(
          crashedEventIds.length,
          "the cut submission must carry the signed Commit and Welcome",
        ).toBeGreaterThan(0);
        await crash.restore();

        await inkson.reload();
        await openOwnAgentDirectChat(inkson, agentSlug);
        await expect(inkson.getByTestId("chat-panel")).toBeVisible({
          timeout: 180_000,
        });
        await expect(inkson.getByTestId("chat-input")).toBeVisible({
          timeout: 30_000,
        });

        const replayed = mlsSubmissions
          .all()
          .filter(
            (events) =>
              events.map((event) => event.eventId).join("|") ===
              crashedEventIds.join("|"),
          );
        expect(
          replayed.length,
          "the cut submission must have been retried after the reload",
        ).toBeGreaterThanOrEqual(2);
        expect(
          mlsSubmissions.distinctEventIds("ak.mls.commit"),
          "a resumed materialization must not author a second Commit",
        ).toHaveLength(1);
        expect(
          mlsSubmissions.distinctEventIds("ak.mls.welcome").length,
          "a resumed materialization must not author a second Welcome",
        ).toBeLessThanOrEqual(1);
        expect(
          keyPackageClaims.count(),
          "a resumed materialization must not claim a second peer KeyPackage",
        ).toBeLessThanOrEqual(1);

        // The canonical binding is idempotent across the crash: every resolve
        // returns the same Realm, main Strand and binding Event, so the generic
        // MLS reconciler never raced a second Direct Conversation into being.
        const resolvedBindings = await bindings.all();
        expect(resolvedBindings.length).toBeGreaterThan(0);
        for (const binding of resolvedBindings) {
          expect(binding).toEqual(resolvedBindings[0]);
        }

        // ── Phase 8: a real user message is answered by the live runtime ──
        const prompt = "请只回复 pong";
        await inkson.getByTestId("chat-input").fill(prompt);
        await jointRealm.alicePage.clickWithPassivePromptRetry(
          inkson.getByTestId("send-chat-button"),
        );
        await expect(
          inkson.getByTestId("chat-message").filter({ hasText: prompt }),
        ).toBeVisible({ timeout: 30_000 });

        const pongBody = inkson
          .getByTestId("content-block-text")
          .filter({ hasText: /^pong(?:\r?\n|$)/ });
        const pongMessage = inkson
          .getByTestId("chat-message")
          .filter({ has: pongBody });
        await expect(pongMessage).toBeVisible({ timeout: 180_000 });
        expect((await pongBody.innerText()).split(/\r?\n/, 1)[0]).toBe("pong");
        await expect(pongMessage).toHaveAttribute(
          "data-crypto-state",
          "plaintext",
        );
        await expect(
          pongMessage.getByTestId("member-badge-agent"),
        ).toBeVisible();
        await expect(
          pongMessage.getByTestId("crypto-status-needs-verification"),
        ).toHaveCount(0);
      } finally {
        await savfoxContext.close();
      }
    },
  );
});

async function openSavfoxArkretChannel(
  savfox: Page,
  savfoxBaseUrl: string,
  savfoxToken: string,
): Promise<void> {
  await savfox.goto(`${savfoxBaseUrl}/channels/edit/arkret`);
  const tokenInput = savfox.getByPlaceholder("Gateway token", { exact: true });
  if (await tokenInput.isVisible()) {
    await tokenInput.fill(savfoxToken);
    await savfox.getByRole("button", { name: "Connect" }).click();
  }
  await expect(
    savfox.getByRole("heading", { name: "Configure Arkret" }),
  ).toBeVisible({ timeout: 30_000 });
}

async function startSavfoxPairing(
  savfox: Page,
  pairingLink: string,
): Promise<void> {
  await savfox
    .getByPlaceholder(
      "https://arkret.example.org/_arkret/open/agent-pairing/resolve#token=...",
      { exact: true },
    )
    .fill(pairingLink);
  const startPairing = savfox.getByRole("button", {
    name: "Start pairing",
    exact: true,
  });
  await expect(startPairing).toBeEnabled();
  await startPairing.click();
}

async function saveSavfoxChannel(savfox: Page): Promise<void> {
  await savfox
    .getByRole("button", { name: "Save changes", exact: true })
    .click();
  await expect(
    savfox.getByRole("heading", { name: "Configure Arkret" }),
  ).toHaveCount(0, { timeout: 120_000 });
}

async function openOwnAgentDirectChat(
  inkson: Page,
  agentSlug: string,
): Promise<void> {
  await expect(inkson.getByTestId("realm-sidebar-tab-direct")).toBeVisible({
    timeout: 120_000,
  });
  await inkson.getByTestId("realm-sidebar-tab-direct").click();
  const ownAgentRow = inkson
    .getByTestId("contact-sidebar-self-group")
    .getByTestId("contact-sidebar-agent-row")
    .filter({ hasText: agentSlug });
  await expect(ownAgentRow).toBeVisible({ timeout: 120_000 });
  await ownAgentRow.click();
}

async function runtimeKeyRequestStatus(
  request: APIRequestContext,
  pairing: PairingHandle,
): Promise<RuntimeKeyRequestStatus> {
  const response = await request.post(
    `${solandBaseUrl()}${RUNTIME_KEY_REQUEST_STATUS_PATH}`,
    {
      data: {
        pairing_request_id: pairing.pairingRequestId,
        pairing_code: pairing.pairingCode,
        agent_id: pairing.agentId,
      },
    },
  );
  const text = await response.text();
  expect(response.status(), text).toBe(200);
  return JSON.parse(text) as RuntimeKeyRequestStatus;
}

/// Fail the agent list query — the only entry point of the approval prompt's
/// periodic fallback poll — so the prompt can only be raised by the
/// notification projection.
async function failAgentListQuery(page: Page): Promise<{
  restore: () => Promise<void>;
}> {
  const handler = async (route: Route) => {
    const outgoing = route.request();
    if (
      outgoing.method() === "GET" &&
      new URL(outgoing.url()).pathname === AGENT_LIST_PATH
    ) {
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({ code: "service_unavailable" }),
      });
      return;
    }
    await route.continue();
  };
  await page.route(AGENT_LIST_GLOB, handler);
  return {
    restore: async () => {
      await page.unroute(AGENT_LIST_GLOB, handler);
    },
  };
}

/// Drop the account stream that carries notification deltas, simulating a lost
/// wakeup while every ordinary request path stays healthy.
async function dropAccountSubscribeStream(page: Page): Promise<{
  blockedCount: () => number;
  restore: () => Promise<void>;
}> {
  let blocked = 0;
  const handler = async (route: Route) => {
    blocked += 1;
    await route.abort("connectionfailed");
  };
  await page.route(isAccountSubscribe, handler);
  return {
    blockedCount: () => blocked,
    restore: async () => {
      await page.unroute(isAccountSubscribe, handler);
    },
  };
}

type MlsTransactionEvent = { kind: string; eventId: string };

/// Event ingress carries `EventInitialSubmission` values, so inspect the
/// nested signed Events rather than the deleted bare-Event request shape.
function mlsTransactionEvents(postData: string | null): MlsTransactionEvent[] {
  if (!postData) {
    return [];
  }
  let body: unknown;
  try {
    body = JSON.parse(postData);
  } catch {
    return [];
  }
  type InitialSubmission = {
    event?: { event_id?: string; kind?: string };
  };
  const container = body as { events?: InitialSubmission[] };
  const submissions = Array.isArray(container.events)
    ? container.events
    : [body as InitialSubmission];
  return submissions
    .map((submission) => submission.event)
    .filter(
      (event): event is NonNullable<InitialSubmission["event"]> =>
        event !== undefined,
    )
    .filter((event) => MLS_TRANSACTION_KINDS.includes(event.kind ?? ""))
    .filter((event) => (event.event_id ?? "") !== "")
    .map((event) => ({ kind: event.kind!, eventId: event.event_id! }));
}

/// Record every MLS Commit / Welcome the client submits, so a resumed
/// materialization can be compared against the one that was cut.
function trackMlsSubmissions(page: Page): {
  all: () => MlsTransactionEvent[][];
  distinctEventIds: (kind: string) => string[];
} {
  const submitted: MlsTransactionEvent[][] = [];
  page.on("request", (outgoing) => {
    if (
      outgoing.method() !== "POST" ||
      new URL(outgoing.url()).pathname !== EVENTS_SUBMIT_PATH
    ) {
      return;
    }
    const events = mlsTransactionEvents(outgoing.postData());
    if (events.length > 0) {
      submitted.push(events);
    }
  });
  return {
    all: () => submitted,
    distinctEventIds: (kind) => [
      ...new Set(
        submitted
          .flat()
          .filter((event) => event.kind === kind)
          .map((event) => event.eventId),
      ),
    ],
  };
}

function countRequests(page: Page, pathname: string): { count: () => number } {
  let seen = 0;
  page.on("request", (outgoing) => {
    if (new URL(outgoing.url()).pathname === pathname) {
      seen += 1;
    }
  });
  return { count: () => seen };
}

/// Abort the first signed MLS Commit / Welcome submission, which is the mid-flow
/// crash point of a Direct Conversation materialization.
async function cutFirstMlsTransactionSubmission(page: Page): Promise<{
  waitForCutSubmission: () => Promise<string[]>;
  restore: () => Promise<void>;
}> {
  let cut = false;
  let resolveCut: (eventIds: string[]) => void = () => {};
  const cutObserved = new Promise<string[]>((resolve) => {
    resolveCut = resolve;
  });
  const handler = async (route: Route) => {
    const outgoing = route.request();
    if (!cut && outgoing.method() === "POST") {
      const events = mlsTransactionEvents(outgoing.postData());
      if (events.length > 0) {
        cut = true;
        resolveCut(events.map((event) => event.eventId));
        await route.abort("connectionfailed");
        return;
      }
    }
    await route.continue();
  };
  await page.route(isEventsSubmit, handler);
  return {
    waitForCutSubmission: () => cutObserved,
    restore: async () => {
      await page.unroute(isEventsSubmit, handler);
    },
  };
}

/// Record the canonical Direct Conversation binding returned by every
/// successful resolve, so the crash/reload chain can assert they never diverge.
function trackDirectConversationBindings(page: Page): {
  all: () => Promise<DirectConversationBinding[]>;
} {
  const pending: Promise<DirectConversationBinding | null>[] = [];
  page.on("response", (response) => {
    if (
      response.request().method() !== "POST" ||
      new URL(response.url()).pathname !== DIRECT_CONVERSATIONS_RESOLVE_PATH ||
      response.status() !== 200
    ) {
      return;
    }
    pending.push(
      response
        .json()
        .then((body: Record<string, string>) =>
          body.state === "found" &&
          body.realm_id &&
          body.main_strand_id &&
          body.binding_event_ref
            ? {
                realm_id: body.realm_id,
                main_strand_id: body.main_strand_id,
                binding_event_ref: body.binding_event_ref,
              }
            : null,
        )
        .catch(() => null),
    );
  });
  return {
    all: async () =>
      (await Promise.all(pending)).filter(
        (binding): binding is DirectConversationBinding => binding !== null,
      ),
  };
}
