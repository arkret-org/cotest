import { openAndPairSecondController } from "../../helpers/paired-controller";
import { agentTopicChats } from "../../helpers/direct-structure";
import {
  expect,
  type APIRequestContext,
  type Browser,
  type BrowserContext,
  type Locator,
  type Page,
  type Request,
  type Route,
  type TestInfo,
} from "../../helpers/arkret-test";
import { readFile } from "node:fs/promises";
import type {
  ActorId,
  AccountId,
  AgentSidecarExchangeProjection,
  AgentSidecarView,
  SidecarEnsureAcceptedOutcome,
} from "../../helpers/generated/spec-wire-objects";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  deliverInviteWithConsentGrant,
  grantInviteConsentArkret,
} from "../../helpers/contact-api";
import {
  decodeIngressEvents,
  type IngressEvent,
} from "../../helpers/event-ingress";
import {
  test as jointTest,
  type JointRealmFixture,
} from "../../helpers/joint-fixture";
import { canonicalJson, expectJsonOk, wireErrCode } from "../../helpers/soland-api";
import {
  serverLoginViaCoauth,
  submitCoauthPasswordCredentials,
} from "../../helpers/real-oidc-login";
import {
  approvePairingLinkOnAuthorizedDevice,
  type DpopUserSession,
  type JointUserPage,
  openUserPage,
  selfPathHeadersForDpopSession,
  uniqueUser,
} from "../../helpers/users";

// Mirrors inkson `APPROVAL_FALLBACK_POLL_INTERVAL`
// (src/components/agent_runtime_approval_prompt.rs). A successfully parsed
// describe without the notification feature alone permits the fallback poll.
// This capable Station must replay notifications after a transport outage.
const APPROVAL_FALLBACK_POLL_MS = 30_000;
const APPROVAL_NOTIFICATION_FEATURE = "ak.feature.agent_runtime_approval_notifications.v1";
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
  lifecycle: string;
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
      const stationDescribe = await expectJsonOk(
        await request.get(`${solandBaseUrl()}/_arkret/describe`),
        "Station describe for approval notifications",
      );
      expect(Array.isArray(stationDescribe.supported_features)).toBe(true);
      expect(stationDescribe.supported_features).toContain(APPROVAL_NOTIFICATION_FEATURE);

      // Bob is a real ordinary member of the source Realm. He is deliberately
      // neither a controller nor an Agent and later proves the non-disclosure
      // boundary against a known Sidecar id.
      if (!lifecycleEvidenceOnly) {
        const consent = await grantInviteConsentArkret(
          request,
          jointRealm.bobSession.grantJwt,
          jointRealm.bob,
          jointRealm.alice.id,
        );
        const delivery = await deliverInviteWithConsentGrant(request, {
          inviterId: jointRealm.alice.id,
          inviterToken: jointRealm.aliceToken,
          realmId: jointRealm.realmId,
          inviteeId: jointRealm.bob.id,
          consentGrantRef: consent.eventRef,
          originServer: "server1",
          recipientServer: "server1",
        });
        expect(delivery.outcome.disclosed_outcome).toBe("delivered");
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
      expect(beforeRequest.lifecycle).toBe("active");
      expect(beforeRequest.runtime_state).toBe("pending_runtime_key");
      expect(beforeRequest.approval_request_id ?? null).toBeNull();
      expect(beforeRequest.authorized_event_ref ?? null).toBeNull();

      const savfoxContext = await browser.newContext();
      const savfox = await savfoxContext.newPage();
      const approvalDetailStatuses: number[] = [];
      inkson.on("response", (response) => {
        const path = new URL(response.url()).pathname;
        if (
          response.request().method() === "GET" &&
          path.startsWith(`${AGENT_LIST_PATH}/`)
        ) {
          approvalDetailStatuses.push(response.status());
        }
      });
      let secondController: JointUserPage | undefined;
      let unaddressedRuntimeContext: BrowserContext | undefined;
      try {
        await openSavfoxArkretChannel(savfox, savfoxBaseUrl, savfoxToken);

        // ── Phase 2: the notification wakeup alone must raise the prompt ──
        // Block list discovery as an independent guard. The announced feature
        // also forbids fallback polling, so the prompt must come from the
        // notification projection.
        if (lifecycleEvidenceOnly) {
          await startSavfoxPairing(savfox, pairingLink);
          await expect(approvalModal).toBeVisible({ timeout: 120_000 });
        } else {
          const listOutage = await failAgentListQuery(inkson);
          try {
            await startSavfoxPairing(savfox, pairingLink);
            await expect(
              approvalModal,
              `Agent detail reads during notification wakeup: ${approvalDetailStatuses.join(",") || "none"}`,
            ).toBeVisible({ timeout: 120_000 });
          } finally {
            await listOutage.restore();
          }
        }

        const inksonCode = (
          await inkson.getByTestId("agent-runtime-approval-code").innerText()
        ).trim();
        const groupedPairingCode = displayPairingCode(firstPairing.pairingCode);
        expect(inksonCode).toBe(groupedPairingCode);
        await expect(
          savfox.getByText(groupedPairingCode, { exact: true }),
        ).toBeVisible();
        await expect(
          savfox.getByText(
            `Waiting for Inkson approval... Compare pairing code ${firstPairing.pairingCode} with the Inkson prompt.`,
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
        expect(firstBinding.lifecycle).toBe("active");
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
        expect(replacementBeforeRequest.lifecycle).toBe("active");
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

        // ── Phase 5: a capable Station replays the durable notification ──
        // A failed notification transport does not grant permission to poll.
        // Keep the visible, online client without list discovery for a full
        // fallback-sized window, then recover the same pending request.
        if (lifecycleEvidenceOnly) {
          await openSavfoxArkretChannel(savfox, savfoxBaseUrl, savfoxToken);
          await startSavfoxPairing(savfox, replacementLink);
          await expect(approvalModal).toBeVisible({
            timeout: 3 * APPROVAL_FALLBACK_POLL_MS,
          });
        } else {
          const streamOutage = await dropAccountSubscribeStream(inkson);
          let listReadsDuringOutage = 0;
          const observeList = (outgoing: Request) => {
            if (outgoing.method() === "GET" &&
                new URL(outgoing.url()).pathname === AGENT_LIST_PATH) {
              listReadsDuringOutage += 1;
            }
          };
          inkson.on("request", observeList);
          let retainedApprovalRequestId: string | undefined;
          try {
            await openSavfoxArkretChannel(savfox, savfoxBaseUrl, savfoxToken);
            await startSavfoxPairing(savfox, replacementLink);
            await expect.poll(async () => {
              retainedApprovalRequestId = await pendingControllerApprovalId(
                request, jointRealm, replacementPairing,
              );
              return Boolean(retainedApprovalRequestId);
            }, { timeout: 120_000 }).toBe(true);
            const outageEndsAt = Date.now() + 3 * APPROVAL_FALLBACK_POLL_MS;
            while (Date.now() < outageEndsAt) {
              expect(await approvalModal.count()).toBe(0);
              expect(listReadsDuringOutage, "supported notifications forbid list fallback").toBe(0);
              // This is an intentional fault duration, not a readiness delay.
              const remaining = outageEndsAt - Date.now();
              if (remaining > 0) await inkson.waitForTimeout(Math.min(1_000, remaining));
            }
            expect(await approvalModal.count()).toBe(0);
            expect(listReadsDuringOutage).toBe(0);
          } finally {
            inkson.off("request", observeList);
            await streamOutage.restore();
          }
          expect(
            streamOutage.blockedCount(),
            "the notification transport must have been cut before creating the request",
          ).toBeGreaterThan(0);
          await expect(approvalModal).toBeVisible({ timeout: 120_000 });
          expect(await pendingControllerApprovalId(request, jointRealm, replacementPairing))
            .toBe(retainedApprovalRequestId);
        }
        await expect(approvalModal).toContainText("replaces the runtime key");
        expect(
          (
            await inkson.getByTestId("agent-runtime-approval-code").innerText()
          ).trim(),
        ).toBe(displayPairingCode(replacementPairing.pairingCode));

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
        const openResponses: string[] = [];
        inkson.on("response", (response) => {
          if (new URL(response.url()).pathname.includes("direct-conversation")) {
            openResponses.push(`${response.request().method()} ${new URL(response.url()).pathname}: ${response.status()}`);
          }
        });
        const crash = await cutFirstMlsTransactionSubmission(inkson);

        await openOwnAgentDirectChat(inkson, agentSlug);
        let crashedEventIds: string[];
        try {
          crashedEventIds = await crash.waitForCutSubmission();
        } catch (error) {
          const toasts = await inkson.getByTestId("toast-item").allTextContents();
          throw new Error(
            `Agent Direct Conversation did not submit MLS: ` +
              JSON.stringify({
                openResponses,
                keyPackageClaims: keyPackageClaims.count(),
                mlsSubmissions: mlsSubmissions.diagnostics(),
                toasts,
                currentUrl: inkson.url(),
              }),
            { cause: error },
          );
        }
        expect(
          crashedEventIds.length,
          "the cut submission must carry the signed Commit and Welcome",
        ).toBeGreaterThan(0);
        const claimRequestsAtCrash = keyPackageClaims.count();
        expect(claimRequestsAtCrash).toBeGreaterThan(0);
        await crash.restore();

        const replayed = () => mlsSubmissions.all().filter(
          (events) => events.map((event) => event.eventId).join("|") === crashedEventIds.join("|"),
        );
        await inkson.reload();
        await openOwnAgentDirectChat(inkson, agentSlug, {
          retryUntilChatReady: true,
          resumedSubmissionReady: async () => replayed().length >= 2 &&
            (await bindings.all()).length > 0,
          diagnostics: () => JSON.stringify(mlsSubmissions.diagnostics()),
        });
        await expect(inkson.getByTestId("chat-panel")).toBeVisible({
          timeout: 180_000,
        });
        await expect(inkson.getByTestId("chat-input")).toBeVisible({
          timeout: 30_000,
        });

        expect(
          replayed().length,
          "the cut submission must have been retried after the reload",
        ).toBeGreaterThanOrEqual(2);
        await testInfo.attach("direct-mls-public-governance-diagnostics", {
          body: JSON.stringify(mlsSubmissions.diagnostics()),
          contentType: "application/json",
        });
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
          "resuming the frozen MLS unit must not make another peer KeyPackage claim request",
        ).toBe(claimRequestsAtCrash);

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

        // Realm receive and its durable signer evidence must survive a reload
        // without an Account notification carrying the Agent reply again.
        const acceptedReplyId = await eventIdFromMessage(pongMessage);
        const accountOutage = await dropAccountSubscribeStream(inkson);
        try {
          await inkson.reload();
          await expect.poll(accountOutage.blockedCount, { timeout: 30_000 }).toBeGreaterThan(0);
          await expect(pongMessage).toBeVisible({ timeout: 180_000 });
          expect(await eventIdFromMessage(pongMessage)).toBe(acceptedReplyId);
          await expect(pongMessage).toHaveAttribute("data-crypto-state", "plaintext");
          await expect(pongMessage.getByTestId("member-badge-agent")).toBeVisible();
          await expect(pongMessage.getByTestId("crypto-status-needs-verification")).toHaveCount(0);
          await expect(inkson.getByText(/GroupStateError\(PendingCommit\)/)).toHaveCount(0);
        } finally {
          await accountOutage.restore();
        }

        await agentTopicChats(inkson, process.env.COTEST_SAVFOX_MODEL_RECEIPTS?.trim() ?? "");

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
            await expect(historicalMessage).toHaveAttribute("data-crypto-state", "plaintext");
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
        expect(secondControllerFlow.accountId).toEqual(
          jointRealm.aliceSession.accountId,
        );
        expect(secondControllerFlow.deviceId).not.toBe(
          jointRealm.alice.deviceId,
        );
        await expect(
          secondController.page.getByTestId("sidecar-security-state"),
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
        const sourceAgent = sourceCard.locator(
          `[data-testid="card-detail-agent-row"][data-agent-id="${firstPairing.agentId}"]`,
        );
        await expect(sourceAgent).toBeVisible({ timeout: 120_000 });
        const sidecarPrompt = "请在私有 Sidecar 中只回复 pong";
        await composeSourceAgentMention(
          sourceCard,
          sourceAgent,
          firstPairing.agentId,
          sidecarPrompt,
        );
        // The unknown-current encrypted control becomes the hidden secure
        // alternate when this source scope resolves to plaintext. Resolve the
        // enabled Send control before click can retain that old DOM node.
        await expect.poll(async () => ({
          enabled: await sourceCard.getByTestId("send-chat-button").isEnabled(),
          route: await sourceCard.getByTestId("composer-send-scope").getAttribute("data-send-route"),
          boundAgent: await sourceCard.locator(
            `[data-testid="mention-chip"][data-mention-principal-id="${firstPairing.agentId}"]`,
          ).count(),
        }), { timeout: 30_000 }).toEqual({ enabled: true, route: "Sidecar", boundAgent: 1 });
        let ensureCutFaults = 0;
        let frozenEnsureBody: string | undefined;
        const ensureCutFault = async (route: Route) => {
          const outgoing = route.request();
          if (outgoing.method() === "POST" && outgoing.postDataJSON()?.phase === "commit") {
            const body = outgoing.postData()!;
            if (frozenEnsureBody === undefined) frozenEnsureBody = body;
            expect(body, "Sidecar cut recovery must replay the original signed request").toBe(frozenEnsureBody);
            if (ensureCutFaults === 0) {
              ensureCutFaults += 1;
              await route.fulfill({
                status: 503,
                contentType: "application/problem+json",
                body: JSON.stringify({
                  type: "https://arkret.org/problems/temporarily_unavailable",
                  title: "Temporarily unavailable",
                  status: 503,
                  detail: "fixture: accepting stream head advanced before the unit",
                }),
              });
              return;
            }
          }
          await route.continue();
        };
        await inkson.route("**/_arkret/self/agent-sidecars:ensure", ensureCutFault);
        let ensured: SidecarEnsureAcceptedOutcome;
        try {
          const ensureResponsePromise = waitForSidecarEnsureAcceptance(inkson, testInfo);
          [ensured] = await Promise.all([
            ensureResponsePromise,
            sourceCard.getByTestId("send-chat-button").click(),
          ]);
          expect(ensureCutFaults).toBe(1);
        } finally {
          await inkson.unroute("**/_arkret/self/agent-sidecars:ensure", ensureCutFault);
        }
        expect(ensured.sidecar_id).toMatch(/^ak:sidecar:/);
        await assertSidecarNonDisclosure(
          request,
          jointRealm,
          ensured.sidecar_id,
        );
        // Embedded cards hide the chat header; verify its derived crypto state
        // and the typed readiness below, then require visible private messages.
        await expect(inkson.getByTestId("sidecar-security-state")).toBeAttached({
          timeout: 120_000,
        });
        await expect(inkson.getByTestId("sidecar-security-state")).toHaveText(
          "E2EE",
          { timeout: 180_000 },
        );
        const readySidecar = await readSidecarCurrent(
          request,
          jointRealm,
          ensured.sidecar_id,
        );
        expect(readySidecar.access_readiness).toBe("ready");
        expect(readySidecar.effective_agent_ids).toContain(firstPairing.agentId);
        // Ensure and request submission are one Send action. Accepted private
        // input clears once; restored private history cannot route a new draft.
        await expect(sourceCard.getByTestId("chat-input")).toHaveValue("", {
          timeout: 30_000,
        });
        await expect(sourceCard.getByTestId("composer-send-scope"))
          .toHaveAttribute("data-send-route", "Shared");

        const requestMessage = sourceCard
          .getByTestId("chat-message")
          .filter({ hasText: sidecarPrompt })
          .last();
        await expect(requestMessage).toBeVisible({ timeout: 30_000 });
        await expect(
          requestMessage.getByTestId("message-private-sidecar-badge"),
        ).toBeVisible();
        const sidecarPongMessage = sourceCard
          .getByTestId("chat-message")
          .filter({
            has: inkson
              .getByTestId("content-block-text")
              .filter({ hasText: /^pong(?:\r?\n|$)/ }),
          })
          .last();
        const sidecarPongBody = sidecarPongMessage
          .getByTestId("content-block-text")
          .filter({ hasText: /^pong(?:\r?\n|$)/ })
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
          effective_agent_ids: readySidecar.effective_agent_ids,
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
        expect(
          decodeURIComponent(new URL(sourceCardUrl).pathname).split("/task/")[1],
          "the accepted source card deep link carries its canonical Strand id",
        ).toMatch(/^ak:strand:[A-Za-z0-9_-]+$/);
        expect(new URL(sourceCardUrl).searchParams.get("tab")).toBe("discussion");
        const paginatedBackfill = await forcePaginatedRealmBackfill(
          secondController.page,
          jointRealm.realmId,
        );
        await secondController.page.goto(sourceCardUrl, {
          waitUntil: "domcontentloaded",
        });
        // Pairing authorized this device without transferring the Account
        // root. Restore that root through the normal recovery UI before the
        // encrypted card and Sidecar history can be projected here.
        const controllerRecoveryKey = jointRealm.aliceSession.recoveryKey;
        expect(
          Boolean(controllerRecoveryKey?.trim().split(/\s+/).length === 24),
          "Device 2 needs the controller's confirmed Recovery Key",
        ).toBe(true);
        await secondController.unlockMlsAccountSecret(controllerRecoveryKey!);
        const secondCard =
          secondController.page.getByTestId("card-detail-modal");
        await expect(secondCard).toBeVisible({ timeout: 120_000 });
        await expect(secondCard.getByTestId("card-detail-tab-discussion"))
          .toHaveAttribute("aria-selected", "true", { timeout: 30_000 });
        await expect(
          secondController.page.getByTestId("sidecar-security-state"),
        ).toBeAttached({ timeout: 180_000 });
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
            has: secondController.page
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
        // The canonical digest is the byte-identity claim; the checkpoint and the
        // full entry are compared as well so a digest that somehow matched a
        // different projection still fails.
        expect(device2Fold.projection_digest).toBe(
          device1Fold.projection_digest,
        );
        expect(JSON.stringify(device2Fold)).toBe(JSON.stringify(device1Fold));
        expect(device2Fold.projection.folded_checkpoint).toEqual(
          device1Fold.projection.folded_checkpoint,
        );
        expect(device1Fold.projection.folded_checkpoint.event_ids.length).toBeGreaterThan(0);
        expect(device1Fold.projection.folded_checkpoint.event_set_digest).toMatch(
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
                  secondControllerFlow.deviceId,
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
        const addressedAgentRow = privacyCard.locator(
          `[data-testid="card-detail-agent-row"][data-agent-id="${firstPairing.agentId}"]`,
        );
        await expect(addressedAgentRow).toBeVisible({ timeout: 120_000 });
        // This source already has an accepted Sidecar mapping. Reopening it
        // restores that private target and converges its native MLS roster;
        // it does not require another ensure/context-attach action.
        await expect(inkson.getByTestId("sidecar-security-state")).toBeAttached({
          timeout: 120_000,
        });
        await expect(inkson.getByTestId("sidecar-security-state")).toHaveText(
          "E2EE",
          { timeout: 180_000 },
        );
        const privacyPrompt = `only addressed runtime may execute ${Date.now()}`;
        await composeSourceAgentMention(
          privacyCard,
          addressedAgentRow,
          firstPairing.agentId,
          privacyPrompt,
        );
        await expect(privacyCard.getByTestId("send-chat-button")).toBeEnabled({
          timeout: 30_000,
        });
        const privacySidecar = await readSidecarCurrent(
          request,
          jointRealm,
          ensured.sidecar_id,
        );
        expect(privacySidecar.access_readiness).toBe("ready");
        expect(privacySidecar.effective_agent_ids).toEqual(
          expect.arrayContaining([
            firstPairing.agentId,
            unaddressedAgent.agentId,
          ]),
        );
        await expect(privacyCard.getByTestId("send-chat-button")).toBeEnabled({
          timeout: 30_000,
        });
        const privacyPongs = privacyCard
          .getByTestId("content-block-text")
          .filter({ hasText: /^pong(?:\r?\n|$)/ });
        const privacyPongsBefore = await privacyPongs.count();
        await privacyCard.getByTestId("send-chat-button").click();
        const privacyRequest = privacyCard
          .getByTestId("chat-message")
          .filter({ hasText: privacyPrompt })
          .last();
        await expect(privacyRequest).toBeVisible({ timeout: 30_000 });
        const privacyFold = await sidecarFoldProjection(
          inkson,
          jointRealm.realmId,
          await eventIdFromMessage(privacyRequest),
        );
        expect(privacyFold.projection.sidecar_id).toBe(ensured.sidecar_id);
        expect(privacyFold.projection.addressed_agent_ids).toEqual([
          firstPairing.agentId,
        ]);
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
        await expect(privacyPongs).toHaveCount(privacyPongsBefore + 1, {
          timeout: 180_000,
        });
        const privacyPong = privacyPongs.last();
        await expect(privacyPong).toBeVisible({ timeout: 180_000 });
        await testInfo.attach("sidecar-unaddressed-runtime-gate", {
          body: Buffer.from(
            JSON.stringify(
              {
                schema: "cotest.sidecar_unaddressed_runtime_gate.v1",
                addressed_agent_id: firstPairing.agentId,
                unaddressed_eligible_agent_id: unaddressedAgent.agentId,
                effective_agent_ids:
                  privacySidecar.effective_agent_ids,
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
        await expect(enabledSwitch).toBeEnabled({ timeout: 30_000 });
        await enabledSwitch.click();
        await expect(inkson.getByTestId("agent-admin-last-op")).toContainText(
          "Paused",
          { timeout: 180_000 },
        );

        await inkson.goto(sourceCardUrl, { waitUntil: "domcontentloaded" });
        const resumedCard = inkson.getByTestId("card-detail-modal");
        await expect(resumedCard).toBeVisible({ timeout: 120_000 });
        await expect(inkson.getByTestId("sidecar-security-state")).toBeAttached({
          timeout: 120_000,
        });
        await expect(inkson.getByTestId("sidecar-security-state")).toHaveText(
          "E2EE",
          { timeout: 180_000 },
        );
        const pausedSidecar = await readSidecarCurrent(
          request,
          jointRealm,
          ensured.sidecar_id,
        );
        expect(pausedSidecar.access_readiness).toBe("ready");
        expect(pausedSidecar.desired_agent_ids).not.toContain(firstPairing.agentId);
        expect(pausedSidecar.effective_agent_ids).not.toContain(firstPairing.agentId);
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
        await resumedCard.getByTestId("card-detail-sidebar-tab-members").click();
        const pausedAgentRow = resumedCard.locator(
          `[data-testid="card-detail-agent-row"][data-agent-id="${firstPairing.agentId}"]`,
        );
        await expect(pausedAgentRow).toBeVisible({ timeout: 120_000 });
        await composeSourceAgentMention(
          resumedCard,
          pausedAgentRow,
          firstPairing.agentId,
          blockedPrompt,
        );
        await resumedCard.getByTestId("send-chat-button").click();
        await expect
          .poll(() => receiptCount(receiptPath), {
            timeout: 15_000,
            intervals: [1_000, 2_000, 3_000],
          })
          .toBe(receiptsBeforePause);
        await inkson.waitForTimeout(5_000);
        inkson.off("request", capturePostPauseSubmissions);
        await expect(resumedCard.getByTestId("chat-input")).toHaveValue(
          new RegExp(blockedPrompt),
        );
        await expect(
          resumedCard.getByTestId("chat-message").filter({ hasText: blockedPrompt }),
        ).toHaveCount(0);
        expect(
          postPauseSubmissions.filter(
            (event) =>
              event.kind === "ak.message.create" ||
              event.kind === "ak.agent.sidecar.exchange.control",
          ),
          "a paused Agent target must not write a private request or implicit completion",
        ).toEqual([]);

        // The private reading surface has no publish dialog. The controller
        // explicitly edits and confirms a fresh ordinary message containing
        // only the chosen text, rather than copying a private Event envelope.
        const sharedBody = await resumedCard.getByTestId("content-block-text")
          .filter({ hasText: /^pong(?:\r?\n|$)/ }).last().innerText();
        expect(sharedBody.trim()).toBe("pong");
        const publishCard = await createSidecarSourceCard(
          inkson, jointRealm.realmId, `Shared result ${Date.now().toString(36)}`,
        );
        await publishCard.getByTestId("chat-input").fill(sharedBody);
        await expect(publishCard.getByTestId("composer-send-scope"))
          .toHaveAttribute("data-send-route", "Shared");
        await expect(inkson.getByTestId("sidecar-security-state")).toHaveCount(0);
        await expect(publishCard.getByTestId("send-chat-button")).toBeEnabled({ timeout: 30_000 });
        const publishRequestPromise = inkson.waitForRequest(
          (outgoing) => outgoing.method() === "POST"
            && new URL(outgoing.url()).pathname === EVENTS_SUBMIT_PATH
            && eventSubmissions(outgoing.postData()).some((event) => event.kind === "ak.message.create"),
          { timeout: 120_000 },
        );
        await publishCard.getByTestId("send-chat-button").click();
        const publishSubmission = eventSubmissions(
          (await publishRequestPromise).postData(),
        ).find((event) => event.kind === "ak.message.create");
        expect(publishSubmission, "explicit shared publish Event").toBeTruthy();
        expect(publishSubmission?.actor_id).toEqual({
          kind: "account", account_id: jointRealm.aliceSession.accountId,
        });
        expect(publishSubmission?.scope_ref).toMatchObject({
          kind: "strand", realm_id: jointRealm.realmId,
        });
        await expect(publishCard.getByTestId("chat-message")
          .filter({ hasText: sharedBody })).toBeVisible({ timeout: 120_000 });
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

jointTest("fresh Agent pairing gates the first send until binding and answers once @fully-implemented", async ({ browser, jointUsers }, testInfo) => {
  const base = process.env.COTEST_SAVFOX_BASE_URL?.trim();
  const token = process.env.COTEST_SAVFOX_TOKEN?.trim();
  jointTest.skip(!base || !token, "PRECONDITION_SAVFOX_UNAVAILABLE: managed Savfox required");
  const inkson = jointUsers.alicePage.page;
  const context = await browser.newContext();
  const savfox = await context.newPage();
  let releaseBinding!: () => void;
  const bindingGate = new Promise<void>((resolve) => { releaseBinding = resolve; });
  let heldBinding: SubmittedEvent | undefined;
  const messages: SubmittedEvent[] = [];
  const phases: string[] = [];
  const observeResolve = async (response: import("@playwright/test").Response) => {
    if (new URL(response.url()).pathname !== DIRECT_CONVERSATIONS_RESOLVE_PATH || !response.ok()) return;
    const body = await response.json();
    phases.push(`${body.state}:${body.peer_mls_admission ?? ""}`);
  };
  inkson.on("response", observeResolve);
  const holdBinding = async (route: Route) => {
    const submitted = eventSubmissions(route.request().postData());
    messages.push(...submitted.filter((event) => event.kind === "ak.message.create"));
    const binding = submitted.find((event) => event.kind === "ak.direct_conversation.bound");
    if (binding) {
      heldBinding = binding;
      await bindingGate;
    }
    await route.continue();
  };
  try {
    // Cold account enrollment can open recovery setup asynchronously after a
    // click. Finish it before provisioning instead of waiting for an HTTP
    // response while the real setup dialog blocks that operation.
    await jointUsers.alicePage.completeRecoveryKeySetupIfPrompted(30_000);
    await openSavfoxArkretChannel(savfox, base!, token!);
    const slug = `cold-savfox-${Date.now().toString(36)}`;
    const pairing = await provisionAgent(inkson, slug);
    await pairManagedSavfoxAgent(inkson, savfox, pairing);
    // Delay the actual binding submission, never fabricate resolver state.
    // This exposes the durable-Welcome/unfinished-binding cold-start window.
    await inkson.route(`**${EVENTS_SUBMIT_PATH}`, holdBinding);
    await openOwnAgentDirectChat(inkson, slug);
    await expect.poll(() => Boolean(heldBinding), { timeout: 180_000 }).toBe(true);
    await expect.poll(() => phases.includes("provisional:durable"), { timeout: 30_000 }).toBe(true);
    await expect(inkson.getByTestId("chat-panel")).toBeVisible();
    const send = inkson.getByTestId("send-chat-button");
    const input = inkson.getByTestId("chat-input");
    const prompt = "请只回复 pong";
    await input.fill(prompt);
    await expect(send).toBeDisabled();
    expect(messages).toHaveLength(0);
    releaseBinding();
    await expect(send).toBeEnabled({ timeout: 180_000 });
    await expect(input).toHaveValue(prompt);
    const accepted = inkson.waitForResponse((response) =>
      new URL(response.url()).pathname === EVENTS_SUBMIT_PATH && response.ok() &&
      eventSubmissions(response.request().postData()).some((event) => event.kind === "ak.message.create"),
      { timeout: 120_000 });
    await send.click();
    await accepted;
    expect(messages).toHaveLength(1);
    expect(messages[0].authorization_ref).toBe("ak.authority.direct_conversation_participant.v1");
    expect(messages[0].semantic_refs).toContainEqual({
      id: heldBinding!.event_id,
      role: "direct_conversation_binding",
      critical: true,
    });
    const pongBody = inkson.getByTestId("content-block-text").filter({ hasText: /^pong(?:\r?\n|$)/ });
    const pong = inkson.getByTestId("chat-message").filter({ has: pongBody });
    await expect(pong).toBeVisible({ timeout: 180_000 });
    await expect(pong).toHaveAttribute("data-crypto-state", "plaintext");
    await expect(pong.getByTestId("member-badge-agent")).toBeVisible();
    await expect(pong.getByTestId("crypto-status-needs-verification")).toHaveCount(0);
    await expect(pong).toHaveCount(1);
    await expect(send).toBeEnabled();
    await testInfo.attach("cold-first-send", { body: JSON.stringify({
      phases, binding: heldBinding!.event_id, firstMessage: messages[0].event_id,
      reply: await eventIdFromMessage(pong), messageSubmissions: messages.length,
    }, null, 2), contentType: "application/json" });
    await testInfo.attach("cold-first-reply", { body: await inkson.screenshot(), contentType: "image/png" });
  } finally {
    releaseBinding();
    inkson.off("response", observeResolve);
    await inkson.unroute(`**${EVENTS_SUBMIT_PATH}`, holdBinding);
    await context.close();
  }
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
  // Fresh pairing must provide ordinary replies without a test-only mode fix.
  // Explicit task delivery remains a separate checkpoint workflow.
  const deliveryMode = savfox.locator("select").filter({
    has: savfox.locator('option[value="interactive_chat"]'),
  });
  await expect(deliveryMode).toHaveValue("interactive_chat");
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
    displayPairingCode(pairing.pairingCode),
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
    resumedSubmissionReady?: () => boolean | Promise<boolean>;
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
          if (await chatPanel.isVisible().catch(() => false)) {
            return (await options.resumedSubmissionReady?.()) ?? true;
          }
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
          return (await chatPanel.isVisible().catch(() => false)) &&
            ((await options.resumedSubmissionReady?.()) ?? true);
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

async function forcePaginatedRealmBackfill(
  page: Page,
  realmId: string,
): Promise<{ requestCount: () => number; restore: () => Promise<void> }> {
  let requests = 0;
  const handler = async (route: Route) => {
    const outgoing = route.request();
    const url = new URL(outgoing.url());
    if (
      outgoing.method() === "POST" &&
      url.pathname === "/_arkret/self/streams/scan" &&
      outgoing.postDataJSON().realm_id === realmId &&
      ["realm", "sidecar"].includes(outgoing.postDataJSON().stream_ref?.kind)
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
      await message
        .locator(
          '[data-testid="content-block-text"], [data-testid="content-block-markdown"]',
        )
        .allInnerTexts()
    )
      .join("\n")
      .trim();
    expect(body).not.toBe("");
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

type SidecarFoldEvidenceEntry = {
  /// Canonical digest of `projection` — the byte-identity check.
  projection_digest: string;
  projection: AgentSidecarExchangeProjection;
};

type SidecarFoldEvidence = {
  schema: string;
  controller_account_id: AccountId;
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
  await page.getByTestId("members-section-my-agents").click();
  const existing = page.locator(
    `[data-testid="member-self-agent-row"][data-agent-id="${agentId}"]`,
  );
  if ((await existing.count()) === 0) {
    await page.getByTestId("open-add-realm-agent-modal-button").click();
    const available = page.locator(
      `[data-testid="available-realm-agent-row"][data-agent-id="${agentId}"]`,
    );
    await expect(available).toBeVisible({ timeout: 120_000 });
    await available.getByTestId("confirm-add-agent-to-realm").click();
    await expect(page.getByTestId("realm-members-status")).toContainText(
      "added agent",
      { timeout: 180_000 },
    );
  }
  const agentRow = page.locator(
    `[data-testid="member-self-agent-row"][data-agent-id="${agentId}"]`,
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

async function waitForSidecarEnsureAcceptance(
  page: Page,
  testInfo: TestInfo,
): Promise<SidecarEnsureAcceptedOutcome> {
  let frozenSubmission: string | undefined;
  const response = await page.waitForResponse(
    async (candidate) => {
      const outgoing = candidate.request();
      if (
        outgoing.method() !== "POST" ||
        new URL(candidate.url()).pathname !== "/_arkret/self/agent-sidecars:ensure"
      ) return false;
      const phase = outgoing.postDataJSON()?.phase;
      if (phase === "commit" || phase === "attach") {
        const body = outgoing.postData()!;
        if (frozenSubmission === undefined) frozenSubmission = body;
        expect(body, "Sidecar ensure retry must retain every frozen request byte").toBe(frozenSubmission);
        if (candidate.status() === 503) {
          const problem = await candidate.json().catch(() => undefined);
          if (wireErrCode(problem) === "temporarily_unavailable") return false;
        }
      }
      return phase === "commit" || phase === "attach" ||
        (phase === "prepare" && candidate.status() >= 400);
    },
    { timeout: 120_000 },
  );
  const text = await response.text();
  const submitted = response.request().postDataJSON();
  if (response.status() !== 200) {
    // Keep only the source selection and complete controller identity. Request
    // headers, credentials, proofs and private signed drafts are excluded.
    await testInfo.attach("sidecar-ensure-failure", {
      body: Buffer.from(JSON.stringify({
        phase: submitted.phase,
        status: response.status(),
        ...(submitted.phase === "prepare" ? {
          source_realm_id: submitted.source_realm_id,
          controller_account_id: submitted.controller_account_id,
          context_ref: submitted.context_ref,
        } : {}),
      }, null, 2)),
      contentType: "application/json",
    });
  }
  expect(response.status(), text).toBe(200);
  const accepted = JSON.parse(text) as SidecarEnsureAcceptedOutcome;
  expect(accepted.status).toBe("accepted");
  expect(accepted.accepted_phase).toBe(submitted.phase);
  expect(accepted.operation_id).toBe(submitted.operation_id);
  return accepted;
}

async function readSidecarCurrent(
  request: APIRequestContext,
  jointRealm: JointRealmFixture,
  sidecarId: string,
): Promise<AgentSidecarView> {
  const url = `${solandBaseUrl().replace(/\/$/, "")}/_arkret/self/agent-sidecars/${encodeURIComponent(sidecarId)}`;
  const response = await request.get(url, {
    headers: selfPathHeadersForDpopSession(jointRealm.aliceSession, "GET", url),
  });
  const text = await response.text();
  expect(response.status(), text).toBe(200);
  const view = JSON.parse(text) as AgentSidecarView;
  expect(view.sidecar.id).toBe(sidecarId);
  expect(view.sidecar.realm_id).toBe(jointRealm.realmId);
  expect(view.sidecar.controller_account_id).toEqual(jointRealm.aliceSession.accountId);
  return view;
}

async function composeSourceAgentMention(
  card: Locator,
  agentRow: Locator,
  agentId: string,
  prompt: string,
): Promise<void> {
  const memberId = await agentRow.getAttribute("data-member-id");
  expect(memberId, "the source member supplies its complete ActorId").not.toBeNull();
  const actor = JSON.parse(memberId!) as ActorId;
  expect(actor.kind).toBe("account");
  if (actor.kind !== "account") throw new Error("Agent member must be an Account");
  expect(actor.account_id.principal_id).toBe(agentId);
  await agentRow.getByTestId("card-detail-member-mention-button").click();
  const chip = card.locator(
    `[data-testid="mention-chip"][data-mention-principal-id="${actor.account_id.principal_id}"][data-mention-station-id="${actor.account_id.station_id}"]`,
  );
  await expect(chip).toBeVisible({ timeout: 30_000 });
  const composer = card.getByTestId("chat-input");
  const mention = (await chip.locator("span").first().innerText()).trim();
  expect(mention).toMatch(/^@/);
  await expect(composer).toHaveValue(`${mention} `);
  // Keep the actual picker insertion so the composer retains the structured
  // mention; a controller/slug string is ordinary text under v1.
  await composer.fill(`${mention} ${prompt}`);
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
  // The toolbar is visible while the Board is still a local pending create.
  // Wait for its accepted canonical route before composing a child List.
  await expect(page).toHaveURL(
    (url) =>
      decodeURIComponent(url.pathname).startsWith(
        `/kanban/${realmId}/board/ak:space:`,
      ),
    { timeout: 120_000 },
  );
  await page.getByTestId("new-column-input").fill("Work");
  await expect(page.getByTestId("new-column-input")).toHaveValue("Work");
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

// The open runtime status has an optional approval id; a replacing runtime
// still has an active key. Only the controller's authenticated exact handle
// projection establishes the pending candidate observed by this fixture.
async function pendingControllerApprovalId(
  request: APIRequestContext,
  jointRealm: JointRealmFixture,
  pairing: PairingHandle,
): Promise<string | undefined> {
  const url = `${solandBaseUrl()}${AGENT_LIST_PATH}/${encodeURIComponent(pairing.agentId)}`;
  const view = await expectJsonOk(await request.get(url, {
    headers: selfPathHeadersForDpopSession(jointRealm.aliceSession, "GET", url),
  }), "controller pending runtime candidate");
  const keyState = view.key_state as Record<string, unknown> | undefined;
  const pending = keyState?.pending_runtime_key_request as Record<string, unknown> | undefined;
  if (!pending) return undefined;
  expect(keyState?.pairing_request_id).toBe(pairing.pairingRequestId);
  expect(pending.pairing_request_id).toBe(pairing.pairingRequestId);
  expect(pending.agent_id).toBe(pairing.agentId);
  expect(typeof pending.approval_request_id).toBe("string");
  expect(pending.approval_request_id).not.toBe("");
  expect(keyState?.approval_request_id).toBe(pending.approval_request_id);
  return pending.approval_request_id as string;
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
  // Routing only affects new requests. Terminate the already-open stream,
  // restore ordinary transport, and prove its reconnect reached the cut.
  await page.context().setOffline(true);
  await page.context().setOffline(false);
  await expect.poll(() => blocked, { timeout: 60_000 }).toBeGreaterThan(0);
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
  governanceMetadata?: Record<string, unknown>;
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
        governanceMetadata: typeof governanceBinding === "object" && governanceBinding !== null
          ? Object.fromEntries([
              "effective_scope", "base_group_state_ref", "previous_epoch",
              "next_epoch", "key_access_revision",
            ].map((field) => [field, (governanceBinding as Record<string, unknown>)[field]]))
          : undefined,
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
        .then((body: Record<string, unknown>) => {
          const coordinates = body.coordinates as Record<string, unknown> | undefined;
          if (body.state !== "found" || !coordinates) return null;
          const { realm_id, main_strand_id, binding_event_ref } = coordinates;
          return typeof realm_id === "string" && realm_id !== "" &&
            typeof main_strand_id === "string" && main_strand_id !== "" &&
            typeof binding_event_ref === "string" && binding_event_ref !== ""
            ? { realm_id, main_strand_id, binding_event_ref }
            : null;
        })
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

function displayPairingCode(pairingCode: string): string {
  expect(pairingCode).toMatch(/^[0-9]{8}$/);
  return `${pairingCode.slice(0, 4)} ${pairingCode.slice(4)}`;
}
