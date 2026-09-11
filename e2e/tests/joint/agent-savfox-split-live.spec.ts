import {
  expect,
  type APIRequestContext,
  type Browser,
  type BrowserContext,
  type Page,
  type Request,
  type Route,
} from "../../helpers/arkret-test";
import { readFile } from "node:fs/promises";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import { grantInviteConsentArkret } from "../../helpers/contact-api";
import {
  decodeIngressEvents,
  type IngressEvent,
} from "../../helpers/event-ingress";
import {
  test as jointTest,
  type JointRealmFixture,
} from "../../helpers/joint-fixture";
import { canonicalJson } from "../../helpers/soland-api";
import {
  approvePairingLinkOnAuthorizedDevice,
  createDpopUserSessionForAccount,
  type DpopUserSession,
  type JointUserPage,
  openUserPage,
  selfPathHeadersForDpopSession,
} from "../../helpers/users";

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
jointTest.setTimeout(1_200_000);

jointTest.describe("Agent Savfox split live @fully-implemented", () => {
  jointTest(
    "pairs, replaces the runtime key, resumes a crashed direct conversation, and answers a real message",
    async ({ browser, jointRealm, request }, testInfo) => {
      jointTest.setTimeout(1_200_000);

      // The scenario can also be selected without the runner's `-StartSavfox`
      // switch, so only run when both endpoints are supplied by the managed
      // runner or an external gateway. Follow the repo convention (README test tiers:
      // "a missing prerequisite must be an explicit test.skip with a
      // machine-readable reason") and skip instead of hard-throwing, which
      // otherwise reds the smoke/full gate on every run.
      const savfoxBaseUrlRaw = process.env.COTEST_SAVFOX_BASE_URL?.trim();
      const savfoxTokenRaw = process.env.COTEST_SAVFOX_TOKEN?.trim();
      if (
        process.env.COTEST_REQUIRE_SAVFOX === "1" &&
        (!savfoxBaseUrlRaw || !savfoxTokenRaw)
      ) {
        throw new Error(
          "COTEST_REQUIRE_SAVFOX=1 but the Savfox base URL or token is missing",
        );
      }
      jointTest.skip(
        !savfoxBaseUrlRaw || !savfoxTokenRaw,
        "PRECONDITION_SAVFOX_UNAVAILABLE: COTEST_SAVFOX_BASE_URL / COTEST_SAVFOX_TOKEN unset (run with scripts/run-joint-e2e.ps1 -StartSavfox or provide an external gateway)",
      );
      const savfoxBaseUrl = savfoxBaseUrlRaw!.replace(/\/$/, "");
      const savfoxToken = savfoxTokenRaw!;
      const inkson = jointRealm.alicePage.page;
      const approvalModal = inkson.getByTestId("agent-runtime-approval-modal");
      const agentSlug = `savfox-live-${Date.now().toString(36)}`;
      const lifecycleEvidenceOnly =
        process.env.COTEST_AGENT_LIFECYCLE_EVIDENCE_ONLY === "1";

      // Bob is a real ordinary member of the source Realm. He is deliberately
      // neither a controller nor an Agent and later proves the non-disclosure
      // boundary against a known Sidecar id.
      if (!lifecycleEvidenceOnly) {
        await grantInviteConsentArkret(
          request,
          jointRealm.bobSession.grantJwt,
          jointRealm.bob,
          jointRealm.alice.id,
        );
        await jointRealm.alicePage.inviteFromAdmin(
          jointRealm.realmId,
          jointRealm.bob.id,
        );
        await jointRealm.bobPage.acceptInvite(jointRealm.realmId);
      }

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
      const commitResponsePromise = inkson.waitForResponse(
        (response) => {
          const outgoing = response.request();
          return (
            response.status() === 201 &&
            outgoing.method() === "POST" &&
            new URL(outgoing.url()).pathname === AGENT_LIST_PATH &&
            (outgoing.postDataJSON() as { phase?: string }).phase === "commit"
          );
        },
        { timeout: 180_000 },
      );
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
      const beforeRequest = await runtimeKeyRequestStatus(
        request,
        firstPairing,
      );
      expect(beforeRequest.status).toBe("active");
      expect(beforeRequest.runtime_state).toBe("pending_runtime_key");
      expect(beforeRequest.approval_request_id ?? null).toBeNull();
      expect(beforeRequest.authorized_event_ref ?? null).toBeNull();

      const savfoxContext = await browser.newContext();
      const savfox = await savfoxContext.newPage();
      let secondController: JointUserPage | undefined;
      let unaddressedRuntimeContext: BrowserContext | undefined;
      try {
        await openSavfoxArkretChannel(savfox, savfoxBaseUrl, savfoxToken);

        // ── Phase 2: the notification wakeup alone must raise the prompt ──
        // The periodic fallback poll is the only other discovery path and its
        // sole entry point is the agent list query. Keep that query failing for
        // the whole window: whether or not a poll tick lands inside it, the
        // fallback cannot discover the request, so a prompt that appears here
        // can only have come from the notification projection.
        if (lifecycleEvidenceOnly) {
          await startSavfoxPairing(savfox, pairingLink);
          await expect(approvalModal).toBeVisible({ timeout: 120_000 });
        } else {
          const listOutage = await failAgentListQuery(inkson);
          try {
            await startSavfoxPairing(savfox, pairingLink);
            await expect(approvalModal).toBeVisible({ timeout: 120_000 });
          } finally {
            await listOutage.restore();
          }
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
        await expect(approvalModal).toHaveCount(0, {
          timeout: 180_000,
        });
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
          .toMatch(/Runtime\s*Listening/);

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
        await expect(inkson.getByTestId("agent-admin")).toBeVisible({
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
        if (lifecycleEvidenceOnly) {
          await openSavfoxArkretChannel(savfox, savfoxBaseUrl, savfoxToken);
          await startSavfoxPairing(savfox, replacementLink);
          await expect(approvalModal).toBeVisible({
            timeout: 3 * APPROVAL_FALLBACK_POLL_MS,
          });
        } else {
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
        }
        await expect(approvalModal).toContainText("replaces the runtime key");
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
        await expect(inkson.getByTestId("agent-admin")).toBeVisible({
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
        await openOwnAgentDirectChat(inkson, agentSlug, {
          retryUntilChatReady: true,
          diagnostics: () => JSON.stringify(mlsSubmissions.diagnostics()),
        });
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
          mlsSubmissions.distinctEventIds("ak.mls.commit", 1),
          "a resumed materialization must not author a second epoch-1 Commit",
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

        if (lifecycleEvidenceOnly) {
          const directConversationUrl = inkson.url();
          const responseEventId = await eventIdFromMessage(pongMessage);
          expect(responseEventId).toMatch(/^ak:event:/);

          const openAgentDetails = async () => {
            await inkson.goto("/settings/agents", {
              waitUntil: "domcontentloaded",
            });
            const row = inkson
              .getByTestId("agent-admin-row")
              .filter({ hasText: agentSlug })
              .first();
            await expect(row).toBeVisible({ timeout: 120_000 });
            await row.click();
          };
          const assertFrozenHistoricalEvent = async () => {
            await inkson.goto(directConversationUrl, {
              waitUntil: "domcontentloaded",
            });
            const historicalMessage = inkson
              .getByTestId("chat-message")
              .filter({ has: inkson.getByTestId("content-block-text").filter({ hasText: /^pong(?:\r?\n|$)/ }) })
              .last();
            await expect(historicalMessage).toBeVisible({ timeout: 180_000 });
            expect(await eventIdFromMessage(historicalMessage)).toBe(responseEventId);
            await expect(
              historicalMessage.getByTestId("member-badge-agent"),
            ).toBeVisible();
            await expect(
              historicalMessage.getByTestId("crypto-status-needs-verification"),
            ).toHaveCount(0);
          };

          await openAgentDetails();
          await inkson.getByTestId("agent-admin-enabled-switch").click();
          await expect(inkson.getByTestId("agent-admin-last-op")).toContainText(
            "Paused. Status: paused.",
            { timeout: 180_000 },
          );
          await assertFrozenHistoricalEvent();

          await openAgentDetails();
          await inkson.getByTestId("agent-admin-enabled-switch").click();
          await expect(inkson.getByTestId("agent-admin-last-op")).toContainText(
            "Resumed. Status: active.",
            { timeout: 180_000 },
          );
          await assertFrozenHistoricalEvent();

          await openAgentDetails();
          await inkson.getByTestId("agent-admin-deactivate-button").click();
          await inkson
            .getByTestId("agent-admin-deactivate-confirm-input")
            .fill("DEACTIVATE");
          await inkson
            .getByTestId("agent-admin-deactivate-confirm-button")
            .click();
          await expect(inkson.getByTestId("agent-admin-last-op")).toContainText(
            "Agent deactivated permanently.",
            { timeout: 180_000 },
          );
          await assertFrozenHistoricalEvent();

          await testInfo.attach("agent-lifecycle-evidence-live", {
            body: Buffer.from(
              JSON.stringify(
                {
                  schema: "cotest.agent_lifecycle_evidence_live.v1",
                  agent_id: firstPairing.agentId,
                  response_event_id: responseEventId,
                  verified_after_lifecycle_states: [
                    "paused",
                    "active",
                    "deactivated",
                  ],
                  historical_event_identity_preserved: true,
                },
                null,
                2,
              ),
            ),
            contentType: "application/json",
          });
          return;
        }

        // A distinct second device for the same controller is paired before
        // Sidecar creation. It remains on the account home surface while
        // Device 1 authors the request and observes the reply, so the two
        // devices begin recovery with deliberately different local histories.
        const secondControllerFlow = await openAndPairSecondController(
          browser,
          request,
          jointRealm,
        );
        secondController = secondControllerFlow.page;
        expect(secondControllerFlow.session.user.id).toBe(
          jointRealm.alice.id,
        );
        expect(secondControllerFlow.session.user.deviceId).not.toBe(
          jointRealm.alice.deviceId,
        );
        await expect(
          secondController.page.getByTestId("sidecar-context-strip"),
        ).toHaveCount(0);

        // ── Phase 9: route a source-card prompt through the private Sidecar ──
        // Direct Conversation above proves the runtime can speak Arkret. This
        // phase proves the actual Sidecar contract: the controller adds the
        // paired runtime to a shared Realm, enables scoped participation, then
        // routes a source-card mention into the private backing scope. Savfox
        // consumes that accepted request and its reply is refolded by Inkson
        // back into the same hosted source card.
        await addAgentToRealm(inkson, jointRealm.realmId, firstPairing.agentId);
        const sourceCard = await createSidecarSourceCard(
          inkson,
          jointRealm.realmId,
          `Sidecar source ${Date.now().toString(36)}`,
        );
        await sourceCard.getByTestId("card-detail-sidebar-tab-members").click();
        const sourceAgent = sourceCard
          .locator(
            `[data-testid="card-detail-agent-row"][data-agent-id="${firstPairing.agentId}"]`,
          )
          .or(
            sourceCard
              .getByTestId("card-detail-agent-row")
              .filter({ hasText: agentSlug }),
          )
          .first();
        await expect(sourceAgent).toBeVisible({ timeout: 120_000 });
        await sourceAgent
          .getByTestId("card-detail-member-mention-button")
          .click();
        const sidecarPrompt = "请在私有 Sidecar 中只回复 pong";
        const composer = sourceCard.getByTestId("chat-input");
        await composer.fill(`@me/${agentSlug} ${sidecarPrompt}`);
        const ensureResponsePromise = inkson.waitForResponse(
          (response) =>
            response.request().method() === "POST" &&
            new URL(response.url()).pathname ===
              "/_arkret/self/agent-sidecars:ensure",
          { timeout: 120_000 },
        );
        await sourceCard.getByTestId("send-chat-button").click();
        const ensureResponse = await ensureResponsePromise;
        const ensureText = await ensureResponse.text();
        expect(ensureResponse.status(), ensureText).toBe(200);
        const ensured = JSON.parse(ensureText) as {
          sidecar_id: string;
          access_readiness: string;
          effective_agent_ids?: string[];
        };
        expect(ensured.sidecar_id).toMatch(/^ak:sidecar:/);
        await assertSidecarNonDisclosure(
          request,
          jointRealm,
          ensured.sidecar_id,
        );
        await expect(inkson.getByTestId("sidecar-context-strip")).toBeVisible({
          timeout: 120_000,
        });
        await expect(inkson.getByTestId("sidecar-security-state")).toHaveText(
          "E2EE",
          { timeout: 180_000 },
        );
        await expect(sourceCard.getByTestId("send-chat-button")).toBeEnabled({
          timeout: 30_000,
        });
        await sourceCard.getByTestId("send-chat-button").click();

        const requestMessage = sourceCard
          .getByTestId("chat-message")
          .filter({ hasText: sidecarPrompt })
          .last();
        await expect(requestMessage).toBeVisible({ timeout: 30_000 });
        await expect(
          requestMessage.getByTestId("message-private-sidecar-badge"),
        ).toBeVisible();
        const sidecarPongBody = sourceCard
          .getByTestId("content-block-text")
          .filter({ hasText: /^pong(?:\r?\n|$)/ })
          .last();
        const sidecarPongMessage = sourceCard
          .getByTestId("chat-message")
          .filter({ has: sidecarPongBody })
          .last();
        await expect(sidecarPongMessage).toBeVisible({ timeout: 180_000 });
        await expect(
          sidecarPongMessage.getByTestId("message-private-sidecar-badge"),
        ).toBeVisible();
        await expect(
          sidecarPongMessage.getByTestId("member-badge-agent"),
        ).toBeVisible();

        const evidence = {
          schema: "cotest.sidecar_savfox_joint_evidence.v1",
          controller_account_id: jointRealm.aliceSession.accountId,
          agent_id: firstPairing.agentId,
          source_realm_id: jointRealm.realmId,
          sidecar_id: ensured.sidecar_id,
          effective_agent_ids: ensured.effective_agent_ids ?? [],
          request_event_id: await eventIdFromMessage(requestMessage),
          response_event_id: await eventIdFromMessage(sidecarPongMessage),
          response_text: (await sidecarPongBody.innerText()).trim(),
          runtime_authorization_ref:
            replacementBinding.authorized_event_ref ?? null,
        };
        expect(evidence.request_event_id).toMatch(/^ak:event:/);
        expect(evidence.response_event_id).toMatch(/^ak:event:/);
        expect(evidence.response_event_id).not.toBe(evidence.request_event_id);
        await testInfo.attach("sidecar-savfox-joint-evidence", {
          body: Buffer.from(JSON.stringify(evidence, null, 2)),
          contentType: "application/json",
        });

        // Device 2 now opens the same source card for the first time. Force the
        // real accepted-Event query down to one item per page, so locator
        // discovery and exchange refold can only succeed by following every
        // opaque cursor and folding the union. Device 1 had an optimistic
        // request fact plus live response; Device 2 has neither.
        const sourceCardUrl = inkson.url();
        const paginatedBackfill = await forcePaginatedRealmBackfill(
          secondController.page,
          jointRealm.realmId,
        );
        await secondController.page.goto(sourceCardUrl, {
          waitUntil: "domcontentloaded",
        });
        const secondCard =
          secondController.page.getByTestId("card-detail-modal");
        await expect(secondCard).toBeVisible({ timeout: 120_000 });
        await expect(
          secondController.page.getByTestId("sidecar-context-strip"),
        ).toBeVisible({ timeout: 180_000 });
        await expect(
          secondController.page.getByTestId("sidecar-security-state"),
        ).toHaveText("E2EE", { timeout: 180_000 });
        const secondRequest = secondCard
          .getByTestId("chat-message")
          .filter({ hasText: sidecarPrompt })
          .last();
        const secondPong = secondCard
          .getByTestId("chat-message")
          .filter({
            has: secondCard
              .getByTestId("content-block-text")
              .filter({ hasText: /^pong(?:\r?\n|$)/ }),
          })
          .last();
        await expect(secondRequest).toBeVisible({ timeout: 180_000 });
        await expect(secondPong).toBeVisible({ timeout: 180_000 });
        await expect
          .poll(() => paginatedBackfill.requestCount(), {
            timeout: 120_000,
            intervals: [500, 1_000, 2_000],
          })
          .toBeGreaterThan(1);

        const device1Projection = await sidecarEchoProjection(
          sourceCard,
          evidence.request_event_id,
          evidence.response_event_id,
        );
        const device2Projection = await sidecarEchoProjection(
          secondCard,
          evidence.request_event_id,
          evidence.response_event_id,
        );
        expect(device2Projection.serializedBytes).toBe(
          device1Projection.serializedBytes,
        );
        expect(device1Projection.requestOccurrences).toBe(1);
        expect(device1Projection.responseOccurrences).toBe(1);
        expect(device2Projection.requestOccurrences).toBe(1);
        expect(device2Projection.responseOccurrences).toBe(1);
        const device1Fold = await sidecarFoldProjection(
          inkson,
          jointRealm.realmId,
          evidence.request_event_id,
        );
        const device2Fold = await sidecarFoldProjection(
          secondController.page,
          jointRealm.realmId,
          evidence.request_event_id,
        );
        // The canonical digest is the byte-identity claim; the frontier and the
        // full entry are compared as well so a digest that somehow matched a
        // different projection still fails.
        expect(device2Fold.projection_digest).toBe(
          device1Fold.projection_digest,
        );
        expect(JSON.stringify(device2Fold)).toBe(JSON.stringify(device1Fold));
        expect(device2Fold.folded_frontier).toEqual(
          device1Fold.folded_frontier,
        );
        expect(device1Fold.folded_frontier.event_ids.length).toBeGreaterThan(0);
        expect(device1Fold.folded_frontier.event_set_digest).toMatch(
          /^sha256:[0-9a-f]{64}$/,
        );
        expect(device1Fold.projection_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
        await testInfo.attach("sidecar-two-device-convergence", {
          body: Buffer.from(
            JSON.stringify(
              {
                schema: "cotest.sidecar_two_device_convergence.v1",
                controller_account_id: jointRealm.aliceSession.accountId,
                device_ids: [
                  jointRealm.alice.deviceId,
                  secondControllerFlow.session.user.deviceId,
                ],
                forced_page_size: 1,
                backfill_request_count: paginatedBackfill.requestCount(),
                fold_projection: device1Fold,
                hosted_echo_projection: device1Projection,
              },
              null,
              2,
            ),
          ),
          contentType: "application/json",
        });
        await paginatedBackfill.restore();

        // ── Phase 10: a live but unaddressed eligible runtime is non-executing ──
        // Bring up a second independently paired Savfox Agent. Both runtimes
        // remain active and effective in the Realm/Sidecar, but the request
        // binding addresses only Agent 1. Agent 2 must consume no model input.
        const unaddressedBaseUrl =
          process.env.COTEST_SAVFOX_UNADDRESSED_BASE_URL?.trim() ?? "";
        const unaddressedToken =
          process.env.COTEST_SAVFOX_UNADDRESSED_TOKEN?.trim() ?? "";
        const unaddressedReceiptPath =
          process.env.COTEST_SAVFOX_UNADDRESSED_MODEL_RECEIPTS?.trim() ?? "";
        expect(unaddressedBaseUrl, "second managed Savfox gateway").not.toBe(
          "",
        );
        expect(unaddressedToken, "second managed Savfox token").not.toBe("");
        expect(
          unaddressedReceiptPath,
          "second managed Savfox receipt path",
        ).not.toBe("");
        unaddressedRuntimeContext = await browser.newContext();
        const unaddressedSavfox = await unaddressedRuntimeContext.newPage();
        await openSavfoxArkretChannel(
          unaddressedSavfox,
          unaddressedBaseUrl,
          unaddressedToken,
        );
        const unaddressedSlug = `savfox-unaddressed-${Date.now().toString(36)}`;
        const unaddressedAgent = await provisionAgent(inkson, unaddressedSlug);
        await pairManagedSavfoxAgent(
          inkson,
          unaddressedSavfox,
          unaddressedAgent,
        );
        await addAgentToRealm(
          inkson,
          jointRealm.realmId,
          unaddressedAgent.agentId,
        );

        const addressedReceiptPath =
          process.env.COTEST_SAVFOX_MODEL_RECEIPTS?.trim() ?? "";
        expect(
          addressedReceiptPath,
          "managed Savfox model receipt path",
        ).not.toBe("");
        const addressedReceiptsBefore =
          await receiptCount(addressedReceiptPath);
        const unaddressedReceiptsBefore = await receiptCount(
          unaddressedReceiptPath,
        );
        await inkson.goto(sourceCardUrl, { waitUntil: "domcontentloaded" });
        const privacyCard = inkson.getByTestId("card-detail-modal");
        await expect(privacyCard).toBeVisible({ timeout: 120_000 });
        await privacyCard
          .getByTestId("card-detail-sidebar-tab-members")
          .click();
        const addressedAgentRow = privacyCard
          .locator(
            `[data-testid="card-detail-agent-row"][data-agent-id="${firstPairing.agentId}"]`,
          )
          .or(
            privacyCard
              .getByTestId("card-detail-agent-row")
              .filter({ hasText: agentSlug }),
          )
          .first();
        await expect(addressedAgentRow).toBeVisible({ timeout: 120_000 });
        await addressedAgentRow
          .getByTestId("card-detail-member-mention-button")
          .click();
        const privacyPrompt = `only addressed runtime may execute ${Date.now()}`;
        await privacyCard
          .getByTestId("chat-input")
          .fill(`@me/${agentSlug} ${privacyPrompt}`);
        const privacyEnsurePromise = inkson.waitForResponse(
          (response) =>
            response.request().method() === "POST" &&
            new URL(response.url()).pathname ===
              "/_arkret/self/agent-sidecars:ensure",
          { timeout: 120_000 },
        );
        await privacyCard.getByTestId("send-chat-button").click();
        const privacyEnsure = await privacyEnsurePromise;
        const privacyEnsureText = await privacyEnsure.text();
        expect(privacyEnsure.status(), privacyEnsureText).toBe(200);
        expect(
          (
            privacyEnsure.request().postDataJSON() as {
              addressed_agent_ids?: string[];
            }
          ).addressed_agent_ids,
        ).toEqual([firstPairing.agentId]);
        const privacyEnsureBody = JSON.parse(privacyEnsureText) as {
          effective_agent_ids?: string[];
        };
        expect(privacyEnsureBody.effective_agent_ids ?? []).toEqual(
          expect.arrayContaining([
            firstPairing.agentId,
            unaddressedAgent.agentId,
          ]),
        );
        await expect(inkson.getByTestId("sidecar-security-state")).toHaveText(
          "E2EE",
          { timeout: 180_000 },
        );
        await expect(privacyCard.getByTestId("send-chat-button")).toBeEnabled({
          timeout: 30_000,
        });
        await privacyCard.getByTestId("send-chat-button").click();
        await expect(
          privacyCard
            .getByTestId("chat-message")
            .filter({ hasText: privacyPrompt })
            .last(),
        ).toBeVisible({ timeout: 30_000 });
        await expect
          .poll(() => receiptCount(addressedReceiptPath), {
            timeout: 180_000,
            intervals: [1_000, 2_000, 5_000],
          })
          .toBe(addressedReceiptsBefore + 1);
        await expect
          .poll(() => receiptCount(unaddressedReceiptPath), {
            timeout: 15_000,
            intervals: [1_000, 2_000, 3_000],
          })
          .toBe(unaddressedReceiptsBefore);
        const privacyPong = privacyCard
          .getByTestId("content-block-text")
          .filter({ hasText: /^pong(?:\r?\n|$)/ })
          .last();
        await expect(privacyPong).toBeVisible({ timeout: 180_000 });
        await testInfo.attach("sidecar-unaddressed-runtime-gate", {
          body: Buffer.from(
            JSON.stringify(
              {
                schema: "cotest.sidecar_unaddressed_runtime_gate.v1",
                addressed_agent_id: firstPairing.agentId,
                unaddressed_eligible_agent_id: unaddressedAgent.agentId,
                effective_agent_ids:
                  privacyEnsureBody.effective_agent_ids ?? [],
                addressed_model_calls_delta: 1,
                unaddressed_model_calls_delta: 0,
              },
              null,
              2,
            ),
          ),
          contentType: "application/json",
        });

        // ── Phase 11: pause fails closed, then explicit publish is allowlisted ──
        // Retain the hosted Sidecar after pause and prove a new private request
        // cannot reach the runtime/model or become implicitly complete.
        const receiptPath = addressedReceiptPath;
        const receiptsBeforePause = await receiptCount(receiptPath);
        await inkson.goto("/settings/agents", {
          waitUntil: "domcontentloaded",
        });
        const adminRow = inkson
          .getByTestId("agent-admin-row")
          .filter({ hasText: agentSlug })
          .first();
        await expect(adminRow).toBeVisible({ timeout: 120_000 });
        await adminRow.click();
        const enabledSwitch = inkson.getByTestId("agent-admin-enabled-switch");
        await expect(enabledSwitch).toBeVisible({ timeout: 30_000 });
        await enabledSwitch.click();
        await expect(inkson.getByTestId("agent-admin-last-op")).toContainText(
          "Paused",
          { timeout: 180_000 },
        );

        await inkson.goto(sourceCardUrl, { waitUntil: "domcontentloaded" });
        const resumedCard = inkson.getByTestId("card-detail-modal");
        await expect(resumedCard).toBeVisible({ timeout: 120_000 });
        await expect(inkson.getByTestId("sidecar-context-strip")).toBeVisible({
          timeout: 120_000,
        });
        await expect(inkson.getByTestId("sidecar-security-state")).toHaveText(
          "E2EE",
          { timeout: 180_000 },
        );
        const postPauseSubmissions: SubmittedEvent[] = [];
        const capturePostPauseSubmissions = (outgoing: {
          method(): string;
          url(): string;
          postData(): string | null;
        }) => {
          if (
            outgoing.method() === "POST" &&
            new URL(outgoing.url()).pathname === EVENTS_SUBMIT_PATH
          ) {
            postPauseSubmissions.push(...eventSubmissions(outgoing.postData()));
          }
        };
        inkson.on("request", capturePostPauseSubmissions);
        const blockedPrompt = `paused runtime must not execute ${Date.now()}`;
        await resumedCard.getByTestId("chat-input").fill(blockedPrompt);
        await resumedCard.getByTestId("send-chat-button").click();
        const blockedMessage = resumedCard
          .getByTestId("chat-message")
          .filter({ hasText: blockedPrompt })
          .last();
        await expect(blockedMessage).toBeVisible({ timeout: 30_000 });
        const blockedEventId = await eventIdFromMessage(blockedMessage);
        expect(blockedEventId).toMatch(/^ak:event:/);
        await expect
          .poll(() => receiptCount(receiptPath), {
            timeout: 15_000,
            intervals: [1_000, 2_000, 3_000],
          })
          .toBe(receiptsBeforePause);
        await inkson.waitForTimeout(5_000);
        inkson.off("request", capturePostPauseSubmissions);
        expect(
          postPauseSubmissions.filter(
            (event) =>
              event.kind === "ak.agent.sidecar.exchange.control" &&
              JSON.stringify(event).includes(blockedEventId),
          ),
          "pause must not implicitly close the blocked exchange",
        ).toEqual([]);

        // Publishing remains an explicit controller action after the runtime
        // has been paused. It emits one ordinary shared message and nothing
        // from the private Sidecar coordinate set.
        const publishOpen = resumedCard.getByTestId("sidecar-publish-open");
        await expect(publishOpen).toBeVisible();
        await publishOpen.click();
        const publishModal = inkson.getByTestId("sidecar-publish-modal");
        await expect(publishModal).toBeVisible();
        const publishRequestPromise = inkson.waitForRequest(
          (outgoing) =>
            outgoing.method() === "POST" &&
            new URL(outgoing.url()).pathname === EVENTS_SUBMIT_PATH,
          { timeout: 120_000 },
        );
        await publishModal.getByTestId("sidecar-publish-confirm").click();
        const publishSubmission = eventSubmissions(
          (await publishRequestPromise).postData(),
        ).find((event) => event.kind === "ak.message.create");
        expect(publishSubmission, "explicit shared publish Event").toBeTruthy();
        expect(JSON.stringify(publishSubmission)).not.toMatch(
          /sidecar_id|backing_circle|private_relation|exchange_id|private_history|context_locator/,
        );
      } finally {
        await unaddressedRuntimeContext?.close();
        await secondController?.close();
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
  const configureHeading = savfox.getByRole("heading", {
    name: "Configure Arkret",
  });
  // The Dioxus shell can render after `goto` resolves. Wait for the actual
  // authenticated-or-login branch before deciding whether a token is needed.
  await expect(tokenInput.or(configureHeading)).toBeVisible({
    timeout: 30_000,
  });
  if (await tokenInput.isVisible()) {
    await tokenInput.fill(savfoxToken);
    const connect = savfox.getByRole("button", { name: "Connect" });
    await expect(connect).toBeEnabled({ timeout: 30_000 });
    await connect.click();
  }
  await expect(configureHeading).toBeVisible({ timeout: 30_000 });
}

async function startSavfoxPairing(
  savfox: Page,
  pairingLink: string,
): Promise<void> {
  const pairingInput = savfox.getByPlaceholder(
    "https://arkret.example.org/_arkret/open/agent-pairing/resolve#token=...",
    { exact: true },
  );
  if ((await pairingInput.count()) === 0) {
    await savfox
      .getByRole("button", { name: "Disconnect agent…", exact: true })
      .click({ timeout: 30_000 });
    await expect(
      savfox.getByText("Disconnect this agent?", { exact: true }),
    ).toBeVisible({ timeout: 30_000 });
    await savfox
      .getByRole("button", { name: "Disconnect agent", exact: true })
      .click({ timeout: 30_000 });
  }
  await expect(pairingInput).toBeVisible({ timeout: 120_000 });
  await pairingInput.fill(pairingLink, { timeout: 30_000 });
  const startPairing = savfox.getByRole("button", {
    name: "Start pairing",
    exact: true,
  });
  await expect(startPairing).toBeEnabled({ timeout: 30_000 });
  await startPairing.click({ timeout: 30_000 });
  const pairingStatus = savfox.locator(".arkret-pairing-status");
  await expect(pairingStatus).toBeVisible({ timeout: 30_000 });
  await expect(pairingStatus).toContainText("Waiting for Inkson approval", {
    timeout: 30_000,
  });
}

async function saveSavfoxChannel(savfox: Page): Promise<void> {
  await savfox
    .getByRole("button", { name: "Save changes", exact: true })
    .click();
  await expect(
    savfox.getByRole("heading", { name: "Configure Arkret" }),
  ).toHaveCount(0, { timeout: 120_000 });
}

async function provisionAgent(
  inkson: Page,
  agentSlug: string,
): Promise<PairingHandle & { pairingLink: string }> {
  await inkson.goto("/settings/agents", { waitUntil: "domcontentloaded" });
  await expect(inkson.getByTestId("agent-admin")).toBeVisible({
    timeout: 120_000,
  });
  await inkson.getByTestId("agent-admin-create-open-button").click();
  await inkson.getByTestId("agent-admin-provision-agent-slug").fill(agentSlug);
  const commitResponsePromise = inkson.waitForResponse(
    (response) => {
      const outgoing = response.request();
      return (
        response.status() === 201 &&
        outgoing.method() === "POST" &&
        new URL(outgoing.url()).pathname === AGENT_LIST_PATH &&
        (outgoing.postDataJSON() as { phase?: string }).phase === "commit"
      );
    },
    { timeout: 180_000 },
  );
  await inkson.getByTestId("agent-admin-provision-button").click();
  const response = await commitResponsePromise;
  const text = await response.text();
  expect(response.status(), text).toBe(201);
  const body = JSON.parse(text) as {
    agent_id: string;
    pairing_request_id: string;
    pairing_code: string;
  };
  await expect(inkson.getByTestId("agent-admin-pairing-card")).toBeVisible({
    timeout: 180_000,
  });
  return {
    agentId: body.agent_id,
    pairingRequestId: body.pairing_request_id,
    pairingCode: body.pairing_code,
    pairingLink: await inkson
      .getByTestId("agent-admin-pairing-url")
      .inputValue(),
  };
}

async function pairManagedSavfoxAgent(
  inkson: Page,
  savfox: Page,
  pairing: PairingHandle & { pairingLink: string },
): Promise<void> {
  const approvalModal = inkson.getByTestId("agent-runtime-approval-modal");
  await startSavfoxPairing(savfox, pairing.pairingLink);
  await expect(approvalModal).toBeVisible({ timeout: 120_000 });
  await expect(inkson.getByTestId("agent-runtime-approval-code")).toHaveText(
    pairing.pairingCode,
  );
  await inkson.getByTestId("agent-runtime-approval-approve").click();
  await expect(approvalModal).toHaveCount(0, { timeout: 180_000 });
  await expect(
    savfox.getByText("Agent paired and channel saved.", { exact: true }),
  ).toBeVisible({ timeout: 180_000 });
  await saveSavfoxChannel(savfox);
  const arkretCard = savfox
    .locator(".channels-card")
    .filter({ hasText: "Arkret" });
  await expect
    .poll(
      async () => {
        await savfox.reload();
        return (await arkretCard.textContent()) ?? "";
      },
      {
        timeout: 120_000,
        intervals: [1_000, 2_000, 5_000],
        message: "second Savfox runtime should enter Listening",
      },
    )
    .toContain("Listening");
}

async function openOwnAgentDirectChat(
  inkson: Page,
  agentSlug: string,
  options: {
    retryUntilChatReady?: boolean;
    diagnostics?: () => string | Promise<string>;
  } = {},
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
  if (!options.retryUntilChatReady) {
    await ownAgentRow.click();
    return;
  }

  const chatPanel = inkson.getByTestId("chat-panel");
  let lastOpenFailure = "no product error was rendered";
  try {
    await expect
      .poll(
        async () => {
          if (await chatPanel.isVisible().catch(() => false)) return true;
          const toastText = (
            await inkson.getByTestId("toast-item").allTextContents()
          )
            .map((text) => text.trim())
            .filter(Boolean)
            .join(" | ");
          if (toastText) lastOpenFailure = toastText;
          const directTab = inkson.getByTestId("realm-sidebar-tab-direct");
          if (
            !(await ownAgentRow.isVisible().catch(() => false)) &&
            (await directTab.isVisible().catch(() => false))
          ) {
            await directTab.click();
            await ownAgentRow
              .waitFor({ state: "visible", timeout: 2_000 })
              .catch(() => undefined);
          }
          if (
            (await ownAgentRow.isVisible().catch(() => false)) &&
            (await ownAgentRow.isEnabled().catch(() => false)) &&
            (await ownAgentRow.getAttribute("data-opening")) !== "true"
          ) {
            await ownAgentRow.click();
          }
          return await chatPanel.isVisible().catch(() => false);
        },
        {
          timeout: 180_000,
          intervals: [500, 1_000, 2_000, 5_000],
          message:
            "the reload must resume the persisted Direct Conversation transaction",
        },
      )
      .toBe(true);
  } catch (error) {
    const diagnostics = (await options.diagnostics?.()) ?? "unavailable";
    throw new Error(
      `persisted Direct Conversation recovery failed: ${lastOpenFailure}; ` +
        `MLS submissions: ${diagnostics}`,
      { cause: error },
    );
  }
}

async function openAndPairSecondController(
  browser: Browser,
  request: APIRequestContext,
  jointRealm: JointRealmFixture,
): Promise<{ page: JointUserPage; session: DpopUserSession }> {
  const coauth = coauthBaseUrl();
  expect(coauth, "joint stack must expose Coauth for Device 2").toBeTruthy();
  const session = await createDpopUserSessionForAccount(
    request,
    `sidecar-controller-device-2-${Date.now()}`,
    jointRealm.aliceSession.account,
    {
      coauthBase: coauth!,
    },
  );
  expect(session, "same-principal Device 2 session").toBeTruthy();
  const device = await openUserPage(browser, session!.user, {
    grantJwt: session!.grantJwt,
    dpopSeedB64url: session!.dpopSeedB64url,
    eventSigningSeedB64url: session!.eventSigningSeedB64url,
    grantId: session!.grantId,
    accountId: session!.accountId,
    principalControlRealmId: session!.principalControlRealmId,
    grantAudience: session!.grantAudience,
  });
  try {
    await jointRealm.alicePage.gotoHome();
    await device.page.goto("/settings/devices/pair", {
      waitUntil: "domcontentloaded",
    });
    await device.page.getByTestId("pair-device-start-button").click();
    const pairingCode = device.page.getByTestId("pair-device-code");
    await expect(pairingCode).toBeVisible({ timeout: 30_000 });
    const code = (await pairingCode.textContent())?.trim() ?? "";
    expect(code).not.toBe("");
    const pairingLink = await device.page
      .getByTestId("pair-device-secret")
      .inputValue();
    await approvePairingLinkOnAuthorizedDevice(
      jointRealm.alicePage,
      pairingLink,
      code,
    );

    await device.page.getByTestId("pair-device-status-button").click();
    await expect(device.page.getByTestId("pair-device-status")).toContainText(
      "Approved.",
      { timeout: 30_000 },
    );
    const viewerUrl = `${solandBaseUrl()}/_arkret/self/account/viewer`;
    await expect
      .poll(
        async () => {
          const response = await request.get(viewerUrl, {
            headers: selfPathHeadersForDpopSession(session!, "GET", viewerUrl),
          });
          if (!response.ok()) return `http-${response.status()}`;
          const body = (await response.json()) as {
            devices?: Array<{ device_id?: string; status?: string }>;
          };
          return (
            body.devices?.find(
              (candidate) => candidate.device_id === session!.user.deviceId,
            )?.status ?? "missing"
          );
        },
        { timeout: 90_000, intervals: [500, 1_000, 2_000] },
      )
      .toBe("active");
    await device.gotoHome();
    await device.acknowledgeRecommendedEncryptionPromptIfVisible(30_000);
    return { page: device, session: session! };
  } catch (error) {
    await device.close();
    throw error;
  }
}

async function forcePaginatedRealmBackfill(
  page: Page,
  realmId: string,
): Promise<{ requestCount: () => number; restore: () => Promise<void> }> {
  let requests = 0;
  const handler = async (route: Route) => {
    const outgoing = route.request();
    const url = new URL(outgoing.url());
    if (
      outgoing.method() === "QUERY" &&
      url.pathname === "/_arkret/self/events" &&
      Array.isArray(outgoing.postDataJSON().realm_ids) &&
      outgoing.postDataJSON().realm_ids.includes(realmId)
    ) {
      requests += 1;
      const body = { ...outgoing.postDataJSON(), limit: 1 };
      await route.continue({ postData: JSON.stringify(body) });
      return;
    }
    await route.fallback();
  };
  await page.route("**/*", handler);
  return {
    requestCount: () => requests,
    restore: () => page.unroute("**/*", handler),
  };
}

async function sidecarEchoProjection(
  card: ReturnType<Page["getByTestId"]>,
  requestEventId: string,
  responseEventId: string,
): Promise<{
  serializedBytes: string;
  echoEventIds: string[];
  requestOccurrences: number;
  responseOccurrences: number;
  echoes: Array<{
    eventId: string;
    body: string;
    actorClass: "agent" | "controller";
    placement: "hosted_source_card";
  }>;
}> {
  const messages = card.getByTestId("chat-message");
  const echoes: Array<{
    eventId: string;
    body: string;
    actorClass: "agent" | "controller";
    placement: "hosted_source_card";
  }> = [];
  for (let index = 0; index < (await messages.count()); index += 1) {
    const message = messages.nth(index);
    const eventId = await eventIdFromMessage(message);
    if (eventId !== requestEventId && eventId !== responseEventId) continue;
    await expect(
      message.getByTestId("message-private-sidecar-badge"),
    ).toBeVisible();
    const body = (
      await message.getByTestId("content-block-text").allInnerTexts()
    )
      .join("\n")
      .trim();
    echoes.push({
      eventId,
      body,
      actorClass:
        (await message.getByTestId("member-badge-agent").count()) > 0
          ? "agent"
          : "controller",
      placement: "hosted_source_card",
    });
  }
  echoes.sort((left, right) =>
    Buffer.from(left.eventId).compare(Buffer.from(right.eventId)),
  );
  const echoEventIds = [...new Set(echoes.map((echo) => echo.eventId))].sort(
    (left, right) => Buffer.from(left).compare(Buffer.from(right)),
  );
  const canonicalProjection = {
    schema: "cotest.sidecar_echo_projection.v1",
    echo_event_ids: echoEventIds,
    echoes,
  };
  return {
    serializedBytes: JSON.stringify(canonicalProjection),
    echoEventIds,
    requestOccurrences: echoes.filter((echo) => echo.eventId === requestEventId)
      .length,
    responseOccurrences: echoes.filter(
      (echo) => echo.eventId === responseEventId,
    ).length,
    echoes,
  };
}

/// Inkson's controller-only fold-cache evidence surface, installed only by a
/// `wasm-localstorage-secrets-test` build. It is a callable handle rather than
/// DOM: nothing here is rendered, screenshotted, or readable by other page
/// script that has not been told the handle exists.
const SIDECAR_FOLD_EVIDENCE_HOOK = "__inkson_sidecar_fold_evidence_v1";
const SIDECAR_FOLD_EVIDENCE_SCHEMA = "inkson.test.sidecar_fold_evidence.v1";

type SidecarFoldFrontier = {
  event_ids: string[];
  event_set_digest: string;
  max_hlc: string;
};

type SidecarFoldEvidenceEntry = {
  exchange_id: string;
  private_strand_id: string;
  status: string;
  terminal_event_id?: string;
  folded_frontier: SidecarFoldFrontier;
  /// Canonical digest of `projection` — the byte-identity check.
  projection_digest: string;
  projection: {
    private_request_event_id: string;
    user_facing_response_event_ids: string[];
    folded_frontier: SidecarFoldFrontier;
  } & Record<string, unknown>;
};

type SidecarFoldEvidence = {
  schema: string;
  controller_account_id: { principal_id: string; station_id: string };
  source_realm_id: string;
  exchanges: SidecarFoldEvidenceEntry[];
};

async function readSidecarFoldEvidence(
  page: Page,
  sourceRealmId: string,
): Promise<SidecarFoldEvidence> {
  const raw = await page.evaluate(
    ([hook, realmId]) => {
      const read = (window as unknown as Record<string, unknown>)[hook];
      if (typeof read !== "function") {
        return null;
      }
      return (read as (realm: string) => string)(realmId);
    },
    [SIDECAR_FOLD_EVIDENCE_HOOK, sourceRealmId] as const,
  );
  expect(
    raw,
    `${SIDECAR_FOLD_EVIDENCE_HOOK} is missing — the bundle was not built with ` +
      "wasm-localstorage-secrets-test",
  ).toBeTruthy();
  const evidence = JSON.parse(raw!) as SidecarFoldEvidence & { error?: string };
  expect(
    evidence.error,
    "fold evidence surface reported an error",
  ).toBeUndefined();
  expect(evidence.schema).toBe(SIDECAR_FOLD_EVIDENCE_SCHEMA);
  return evidence;
}

/// Wait until this device's fold cache holds the exchange that carries
/// `requestEventId`, then return that entry.
async function sidecarFoldProjection(
  page: Page,
  sourceRealmId: string,
  requestEventId: string,
): Promise<SidecarFoldEvidenceEntry> {
  let entry: SidecarFoldEvidenceEntry | undefined;
  await expect
    .poll(
      async () => {
        const evidence = await readSidecarFoldEvidence(page, sourceRealmId);
        entry = evidence.exchanges.find(
          (candidate) =>
            candidate.projection.private_request_event_id === requestEventId,
        );
        return entry !== undefined;
      },
      { timeout: 180_000, intervals: [500, 1_000, 2_000] },
    )
    .toBe(true);
  return entry!;
}

async function addAgentToRealm(
  page: Page,
  realmId: string,
  agentId: string,
): Promise<void> {
  await page.goto(`/realms/${realmId}/members`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page.getByTestId("realm-members-panel")).toBeVisible({
    timeout: 120_000,
  });
  const existing = page.locator(
    `[data-testid="member-self-agent-row"][data-agent-did="${agentId}"]`,
  );
  if ((await existing.count()) === 0) {
    await page.getByTestId("open-add-realm-agent-modal-button").click();
    const available = page.locator(
      `[data-testid="available-realm-agent-row"][data-agent-did="${agentId}"]`,
    );
    await expect(available).toBeVisible({ timeout: 120_000 });
    await available.getByTestId("confirm-add-agent-to-realm").click();
    await expect(page.getByTestId("realm-members-status")).toContainText(
      "added agent",
      { timeout: 180_000 },
    );
  }
  const agentRow = page.locator(
    `[data-testid="member-self-agent-row"][data-agent-did="${agentId}"]`,
  );
  await expect(agentRow).toBeVisible({ timeout: 120_000 });
  const reply = agentRow.getByTestId("member-agent-reply-toggle");
  const mention = agentRow.getByTestId("member-agent-mention-toggle");
  if ((await reply.getAttribute("aria-checked")) !== "true") {
    await reply.click();
  }
  if ((await mention.getAttribute("aria-checked")) !== "true") {
    await mention.click();
  }
  await expect
    .poll(
      async () => [
        await reply.getAttribute("aria-checked"),
        await mention.getAttribute("aria-checked"),
      ],
      { timeout: 120_000 },
    )
    .toEqual(["true", "true"]);
}

async function createSidecarSourceCard(
  page: Page,
  realmId: string,
  title: string,
) {
  await page.goto(`/kanban/${realmId}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible({
    timeout: 120_000,
  });
  await page.getByTestId("new-board-toggle").click();
  await page.getByTestId("new-board-title-input").fill(title);
  await page.getByTestId("create-board-space-button").click();
  await expect(page.getByTestId("add-column-button")).toBeVisible({
    timeout: 120_000,
  });
  await page.getByTestId("new-column-input").fill("Work");
  await page.getByTestId("add-column-button").click();
  const column = page.getByTestId("kanban-column").filter({ hasText: "Work" });
  await expect(column).toBeVisible({ timeout: 120_000 });
  await column.getByTestId("add-card-button").click();
  await column.getByTestId("new-card-title-input").fill(title);
  await column.getByTestId("save-card-button").click();
  const card = page.getByTestId("kanban-card").filter({ hasText: title });
  await expect(card).toBeVisible({ timeout: 120_000 });
  await card.click();
  const detail = page.getByTestId("card-detail-modal");
  await expect(detail).toBeVisible({ timeout: 30_000 });
  return detail;
}

async function assertSidecarNonDisclosure(
  request: APIRequestContext,
  jointRealm: JointRealmFixture,
  sidecarId: string,
): Promise<void> {
  const base = solandBaseUrl().replace(/\/$/, "");
  const detailUrl = `${base}/_arkret/self/agent-sidecars/${encodeURIComponent(sidecarId)}`;
  const controllerView = await request.get(detailUrl, {
    headers: selfPathHeadersForDpopSession(
      jointRealm.aliceSession,
      "GET",
      detailUrl,
    ),
  });
  expect(controllerView.status(), await controllerView.text()).toBe(200);

  const ordinaryMemberView = await request.get(detailUrl, {
    headers: selfPathHeadersForDpopSession(
      jointRealm.bobSession,
      "GET",
      detailUrl,
    ),
  });
  const ordinaryMemberText = await ordinaryMemberView.text();
  expect(ordinaryMemberView.status(), ordinaryMemberText).toBe(404);
  expect(ordinaryMemberText).not.toContain(sidecarId);

  const listUrl = `${base}/_arkret/self/agent-sidecars?realm_id=${encodeURIComponent(jointRealm.realmId)}`;
  const ordinaryMemberList = await request.get(listUrl, {
    headers: selfPathHeadersForDpopSession(
      jointRealm.bobSession,
      "GET",
      listUrl,
    ),
  });
  const ordinaryMemberListText = await ordinaryMemberList.text();
  expect(ordinaryMemberList.status(), ordinaryMemberListText).toBe(200);
  expect(ordinaryMemberListText).not.toContain(sidecarId);
  expect(ordinaryMemberListText).not.toMatch(
    /backing_circle|private_strand|agent_sidecar_of|exchange_id/,
  );

  const circleListUrl = `${base}/_arkret/self/circles?realm_id=${encodeURIComponent(jointRealm.realmId)}`;
  const ordinaryCircleList = await request.get(circleListUrl, {
    headers: selfPathHeadersForDpopSession(
      jointRealm.bobSession,
      "GET",
      circleListUrl,
    ),
  });
  const ordinaryCircleListText = await ordinaryCircleList.text();
  expect(ordinaryCircleList.status(), ordinaryCircleListText).toBe(200);
  expect(ordinaryCircleListText).not.toContain(sidecarId);
  expect(ordinaryCircleListText).not.toContain("agent_sidecar_of");

  const anonymousView = await request.get(detailUrl);
  const anonymousText = await anonymousView.text();
  expect([401, 404]).toContain(anonymousView.status());
  expect(anonymousText).not.toContain(sidecarId);
}

async function eventIdFromMessage(message: ReturnType<Page["getByTestId"]>) {
  return message.evaluate((element) => {
    const candidates = [
      element.getAttribute("data-event-id"),
      element.id.replace(/^chat-msg-/, ""),
      element.querySelector("[data-event-id]")?.getAttribute("data-event-id"),
    ];
    return candidates.find((value) => value?.startsWith("ak:event:")) ?? "";
  });
}

async function runtimeKeyRequestStatus(
  request: APIRequestContext,
  pairing: PairingHandle,
): Promise<RuntimeKeyRequestStatus> {
  const response = await request.post(
    `${solandBaseUrl()}${RUNTIME_KEY_REQUEST_STATUS_PATH}`,
    {
      headers: { "content-type": "application/json" },
      data: canonicalJson({
        pairing_request_id: pairing.pairingRequestId,
        pairing_code: pairing.pairingCode,
        agent_id: pairing.agentId,
      }),
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

type MlsTransactionEvent = {
  kind: string;
  eventId: string;
  nextEpoch?: number;
};
/// The signed Event carried by an `EventInitialSubmission`; the shared decoder
/// owns the wrapper shape.
type SubmittedEvent = IngressEvent;

function eventSubmissions(postData: string | null): SubmittedEvent[] {
  return decodeIngressEvents(postData, {
    context: "Agent split-live Event ingress",
  });
}

/// Event ingress carries `EventInitialSubmission` values, so inspect the
/// nested signed Events rather than the deleted bare-Event request shape.
function mlsTransactionEvents(postData: string | null): MlsTransactionEvent[] {
  return eventSubmissions(postData)
    .filter((event) => MLS_TRANSACTION_KINDS.includes(event.kind ?? ""))
    .filter((event) => (event.event_id ?? "") !== "")
    .map((event) => {
      const governanceBinding = event.payload?.governance_binding;
      const nextEpoch =
        typeof governanceBinding === "object" && governanceBinding !== null
          ? (governanceBinding as Record<string, unknown>).next_epoch
          : undefined;
      return {
        kind: event.kind!,
        eventId: event.event_id!,
        nextEpoch: typeof nextEpoch === "number" ? nextEpoch : undefined,
      };
    });
}

async function receiptCount(path: string): Promise<number> {
  try {
    return (await readFile(path, "utf8"))
      .split(/\r?\n/)
      .filter((line) => line.trim() !== "").length;
  } catch {
    return 0;
  }
}

/// Record every MLS Commit / Welcome the client submits, so a resumed
/// materialization can be compared against the one that was cut.
function trackMlsSubmissions(page: Page): {
  all: () => MlsTransactionEvent[][];
  distinctEventIds: (kind: string, nextEpoch?: number) => string[];
  diagnostics: () => unknown;
} {
  const submitted: MlsTransactionEvent[][] = [];
  const outcomes: Array<{
    eventIds: string[];
    status: number | "failed" | "pending";
    failure?: string;
  }> = [];
  const tracked = new Map<Request, number>();
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
      outcomes.push({
        eventIds: events.map((event) => event.eventId),
        status: "pending",
      });
      tracked.set(outgoing, outcomes.length - 1);
    }
  });
  page.on("response", (response) => {
    const index = tracked.get(response.request());
    if (index !== undefined) {
      outcomes[index].status = response.status();
    }
  });
  page.on("requestfailed", (request) => {
    const index = tracked.get(request);
    if (index !== undefined) {
      outcomes[index].status = "failed";
      outcomes[index].failure = request.failure()?.errorText;
    }
  });
  return {
    all: () => submitted,
    diagnostics: () => ({ submissions: submitted, outcomes }),
    distinctEventIds: (kind, nextEpoch) => [
      ...new Set(
        submitted
          .flat()
          .filter(
            (event) =>
              event.kind === kind &&
              (nextEpoch === undefined || event.nextEpoch === nextEpoch),
          )
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
    waitForCutSubmission: async () => {
      let timeout: ReturnType<typeof setTimeout> | undefined;
      try {
        return await Promise.race([
          cutObserved,
          new Promise<string[]>((_, reject) => {
            timeout = setTimeout(
              () =>
                reject(
                  new Error(
                    "timed out waiting for the first signed MLS Commit / Welcome submission",
                  ),
                ),
              180_000,
            );
          }),
        ]);
      } finally {
        if (timeout !== undefined) clearTimeout(timeout);
      }
    },
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
