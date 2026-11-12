import { accountActorId } from "./coland-api";
import { selectProductOptionByLabel } from "./product-select";
import { boardSwitcher, newBoardTrigger, addBoardList, prepareBoardTitle, submitBoardCardDraft } from "./kanban-product-ui";
import { accountRow, actorRow } from "./product-locators";
import { enterSecretText } from "./secret-input";
// Shared product UI actions; no session or protocol outcome is injected.
import { expect, type Page, type Route, type Request, type TestInfo, type Locator } from './arkret-test';
import { assertAuthoritySubmitOutcome, sdkEventDerivedIds, wireErrCode } from './coland-api';
import { decodeIngressEvents, type IngressEvent as SubmittedEvent } from './event-ingress';
import type { SidecarEnsureAcceptedResponseBody, AccountId, ActorId } from './generated/spec-wire-objects';
export type PairingHandle={agentId:string;pairingRequestId:string;pairingCode:string};
const AGENT_LIST_PATH='/_arkret/self/agents';
const EVENTS_SUBMIT_PATH='/_arkret/self/events';
const isEventsSubmit=({pathname}:URL)=>pathname===EVENTS_SUBMIT_PATH;
const eventSubmissions=(data:string|null)=>decodeIngressEvents(data,{context:'Agent product UI ingress'});


export async function openSavfoxArkretChannel(
  savfox: Page,
  savfoxBaseUrl: string,
  savfoxToken: string,
): Promise<void> {
  await savfox.goto(`${savfoxBaseUrl}/channels/edit/arkret`);
  const tokenInput = savfox.getByLabel("Gateway token", { exact: true });
  const configureHeading = savfox.getByRole("heading", {
    name: "Configure channel", exact: true,
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
  const missingConfiguration = savfox.locator(".error-message").filter({
    hasText: "Channel configuration was not found",
  });
  const deliveryMode = savfox.getByRole("combobox", { name: "Delivery mode", exact: true });
  await expect.poll(async () => {
    if (await missingConfiguration.isVisible()) return "missing";
    return await deliveryMode.isEnabled() ? "loaded" : "loading";
  }, { timeout: 30_000 }).not.toBe("loading");
  if (await missingConfiguration.isVisible()) {
    // An isolated gateway has no saved channel yet. Use the product's add
    // form instead of attempting to edit a nonexistent configuration.
    await savfox.goto(`${savfoxBaseUrl}/channels/add`);
    await expect(configureHeading).toBeVisible({ timeout: 30_000 });
    await selectProductOptionByLabel(savfox.getByRole("combobox", {
      name: "Messaging platform", exact: true,
    }), "Arkret");
  }
  await expect(savfox.getByRole("combobox", { name: "Messaging platform", exact: true })).toHaveText("Arkret");
  // Fresh pairing must provide ordinary replies without a test-only mode fix.
  // Explicit task delivery remains a separate checkpoint workflow.
  await expect(deliveryMode).toBeEnabled({ timeout: 30_000 });
  await expect(deliveryMode).toHaveText("interactive_chat");
}


export async function startSavfoxPairing(
  savfox: Page,
  pairingLink: string,
): Promise<void> {
  const pairingInput = savfox.getByLabel("Inkson pairing link", { exact: true });
  await expect(pairingInput).toBeVisible({ timeout: 120_000 });
  await expect(pairingInput).toBeEnabled({ timeout: 120_000 });
  const startPairing = savfox.getByRole("button", {
    name: "Start pairing / Check approval",
    exact: true,
  });
  await enterSecretText(savfox, pairingInput, pairingLink);
  const savedConfiguration = new URL(savfox.url()).pathname.startsWith("/channels/edit/");
  const ready = await expect(startPairing).toBeEnabled({ timeout: 5_000 })
    .then(() => true, () => false);
  if (!ready && savedConfiguration) {
    await savfox.getByRole("checkbox", { name: "Confirm disconnecting the current agent", exact: true }).check();
    await savfox.getByRole("button", { name: "Disconnect current agent", exact: true }).click();
    await expect(savfox.locator(".arkret-pairing")).toContainText("Disconnected. Paste a new Inkson pairing link to connect another agent.");
    await enterSecretText(savfox, pairingInput, pairingLink);
  }
  await expect(startPairing).toBeEnabled({ timeout: 30_000 });
  await startPairing.click({ timeout: 30_000 });
  const pairingStatus = savfox.locator(".arkret-pairing");
  await expect(pairingStatus).toBeVisible({ timeout: 30_000 });
  await expect(pairingStatus).toContainText("Waiting for Inkson approval", {
    timeout: 30_000,
  });
}


export async function saveSavfoxChannel(savfox: Page): Promise<void> {
  await savfox
    .getByRole("button", { name: "Save channel", exact: true })
    .click();
  await expect(savfox.locator(".error-message")).toHaveText("Channel saved", { timeout: 120_000 });
  await savfox.getByRole("button", { name: "Back to channels", exact: true }).click();
  await expect(
    savfox.getByRole("heading", { name: "Configure channel", exact: true }),
  ).toHaveCount(0, { timeout: 120_000 });
}


export async function provisionAgent(
  inkson: Page,
  agentSlug: string,
): Promise<PairingHandle & { pairingLink: string }> {
  await inkson.goto("/agents", { waitUntil: "domcontentloaded" });
  await expect(inkson.locator(".agent-admin")).toBeVisible({
    timeout: 120_000,
  });
  await inkson.locator(".agent-admin-create-open-button").click();
  await inkson.locator(".agent-admin-provision-agent-slug").locator("input, textarea").fill(agentSlug);
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
  await inkson.locator(".agent-admin-provision-button").click();
  const response = await commitResponsePromise;
  const text = await response.text();
  expect(response.status(), text).toBe(201);
  const body = JSON.parse(text) as {
    agent_id: string;
    pairing_request_id: string;
    pairing_code: string;
  };
  const pairingDeadline = Date.now() + 180_000;
  const remainingPairingBudget = () => Math.max(1, pairingDeadline - Date.now());
  await expect(
    actorRow(inkson, ".agent-admin-row", accountActorId(body.agent_id)),
  ).toHaveAttribute("aria-pressed", "true", { timeout: remainingPairingBudget() });
  await expect(inkson.locator(".agent-admin-slug-title")).toHaveText(agentSlug, {
    timeout: remainingPairingBudget(),
  });
  await expect(inkson.locator(".agent-admin-pairing-card")).toBeVisible({
    timeout: remainingPairingBudget(),
  });
  return {
    agentId: body.agent_id,
    pairingRequestId: body.pairing_request_id,
    pairingCode: body.pairing_code,
    pairingLink: await inkson
      .locator(".agent-admin-pairing-url")
      .inputValue(),
  };
}


export async function pairManagedSavfoxAgent(
  inkson: Page,
  savfox: Page,
  pairing: PairingHandle & { pairingLink: string },
): Promise<void> {
  const approvalModal = inkson.locator(".agent-runtime-approval-dialog");
  await startSavfoxPairing(savfox, pairing.pairingLink);
  await expect(approvalModal).toBeVisible({ timeout: 120_000 });
  await expect(inkson.locator(".device-pair-approval-code")).toHaveText(
    displayPairingCode(pairing.pairingCode),
  );
  await inkson.locator(".agent-runtime-approval-dialog").getByRole("button", { name: "Approve", exact: true }).click();
  await expect(approvalModal).toHaveCount(0, { timeout: 180_000 });
  await expect(
    savfox.locator(".arkret-pairing"),
  ).toContainText("Agent paired and channel saved", { timeout: 180_000 });
  await saveSavfoxChannel(savfox);
  const arkretCard = savfox
    .locator(".channels-card")
    .filter({ hasText: "Arkret" });
  await expect(arkretCard).toHaveCount(1);
  await arkretCard.getByRole("button", { name: "Channel actions", exact: true }).click();
  await savfox.getByRole("menu", { name: "Channel actions", exact: true })
    .getByRole("menuitem", { name: "Health", exact: true }).click();
  await expect(savfox).toHaveURL(url => /^\/channels\/health\/arkret(?:-|$)/.test(url.pathname));
  const health = savfox.getByText(/Runtime_pairing_state:/);
  await expect
    .poll(
      async () => {
        await savfox.getByRole("button", { name: "Refresh", exact: true }).click({ timeout: 5_000 });
        const status = await health.textContent({ timeout: 2_000 }).catch(() => "");
        return {
          paired: /Runtime_pairing_state:\s*paired\b/.test(status ?? ""),
          listening: /Runtime_phase:\s*Listening\b/.test(status ?? ""),
        };
      },
      {
        timeout: 120_000,
        intervals: [1_000, 2_000, 5_000],
        message: "second Savfox runtime should enter Listening",
      },
    )
    .toEqual({ paired: true, listening: true });
}


export async function addAgentToRealm(
  page: Page,
  realmId: string,
  agentId: string,
): Promise<void> {
  await page.goto(`/realms/${realmId}/members`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page.locator(".realm-members-panel")).toBeVisible({
    timeout: 120_000,
  });
  await page.getByRole("button", { name: "My agents", exact: true }).click();
  const existing = actorRow(page, ".member-self-agent-row", accountActorId(agentId));
  if ((await existing.count()) === 0) {
    await page.locator(".open-add-realm-agent-modal-button").click();
    const available = actorRow(page.locator(".add-realm-agent-modal"), ".member-self-agent-row", accountActorId(agentId));
    await expect(available).toBeVisible({ timeout: 120_000 });
    const isTargetJoin = (event: SubmittedEvent) => {
      const member = event.payload?.member_id as { kind?: string; account_id?: AccountId } | undefined;
      return event.kind === "ak.member.state" && event.realm_id === realmId
        && event.payload?.membership === "join" && member?.kind === "account"
        && member.account_id?.principal_id === agentId;
    };
    const submittedJoin = page.waitForResponse(response => {
      const outgoing = response.request();
      return outgoing.method() === "POST" && new URL(response.url()).pathname === EVENTS_SUBMIT_PATH
        && eventSubmissions(outgoing.postData()).some(isTargetJoin);
    }, { timeout: 180_000 });
    await available.locator(".member-agent-add-to-realm").click();
    const joinResponse = await submittedJoin;
    const joinOutcome = await joinResponse.json() as Record<string, unknown>;
    expect(joinResponse.ok(), `Agent join HTTP ${joinResponse.status()}: ${String(joinOutcome.detail ?? "missing Problem detail")}`)
      .toBe(true);
    const join = eventSubmissions(joinResponse.request().postData()).find(isTargetJoin)!;
    assertAuthoritySubmitOutcome(joinOutcome, join, "normal controller-authored Agent first join");
    await expect(page.locator(".add-realm-agent-modal")).toHaveCount(0, { timeout: 180_000 });
    await expect(page.locator(".realm-members-panel > .write-status")).toContainText(
      "added agent",
      { timeout: 180_000 },
    );
  }
  const agentRow = actorRow(page, ".member-self-agent-row", accountActorId(agentId));
  await expect(agentRow).toBeVisible({ timeout: 120_000 });
  const reply = agentRow.getByRole("checkbox", { name: "Reply as agent", exact: true });
  const mention = agentRow.getByRole("checkbox", { name: "Accept @mentions", exact: true });
  // This controlled value changes after the real server acknowledgement.
  // Send one normal activation, then wait for the accepted value to render.
  if (!await reply.isChecked()) await reply.click();
  await expect(reply).toBeChecked({ timeout: 120_000 });
  if (!await mention.isChecked()) await mention.click();
  await expect(mention).toBeChecked({ timeout: 120_000 });
}


/** Activate the retained private draft until its first real ensure handoff. */
export async function submitSidecarComposerDraft(card: Locator): Promise<void> {
  const page = card.page();
  const input = card.locator(".chat-input");
  const original = await input.inputValue();
  expect(original.length > 0, "the private draft must be prepared before Send").toBe(true);
  let started = false;
  let ordinaryMessage = false;
  const observe = (request: Request) => {
    if (request.method() !== "POST") return;
    const path = new URL(request.url()).pathname;
    if (path === "/_arkret/self/agent-sidecars:ensure") started = true;
    if (!started && path === EVENTS_SUBMIT_PATH) {
      ordinaryMessage ||= eventSubmissions(request.postData()).some(event => event.kind === "ak.message.create");
    }
  };
  page.on("request", observe);
  try {
    await page.bringToFront();
    await expect(async () => {
      expect(ordinaryMessage, "a private intent must not fall through to ordinary publication").toBe(false);
      if (started) return;
      expect(await input.inputValue() === original, "retain the complete private draft before handoff").toBe(true);
      await expect(card.locator(".mention-chip")).toHaveCount(1, { timeout: 1_000 });
      await expect(card.locator(".composer-send-scope")).toContainText(/^Private Sidecar:/, { timeout: 1_000 });
      const send = card.locator(".send-chat-button");
      await expect(send).toBeEnabled({ timeout: 1_000 });
      if (!started) await send.click({ timeout: 2_000 });
      await expect.poll(() => started, { timeout: 2_000 }).toBe(true);
    }).toPass({ timeout: 30_000, intervals: [250, 500, 1_000] });
  } finally {
    page.off("request", observe);
  }
}

export async function waitForSidecarEnsureAcceptance(
  page: Page,
  testInfo: TestInfo,
): Promise<SidecarEnsureAcceptedResponseBody> {
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
  const accepted = JSON.parse(text) as SidecarEnsureAcceptedResponseBody;
  expect(accepted.status).toBe("accepted");
  expect(accepted.accepted_phase).toBe(submitted.phase);
  expect(accepted.operation_id).toBe(submitted.operation_id);
  return accepted;
}


export async function composeSourceAgentMention(
  card: Locator,
  agentRow: Locator,
  agentId: string,
  prompt: string,
): Promise<void> {
  const identity = await agentRow.locator(".card-detail-member-identity").innerText();
  const match = /^Agent: (\S+) · Principal: (\S+) · Station: (\S+)$/.exec(identity);
  expect(match, "the source member supplies its complete Account identity").not.toBeNull();
  expect(match![1]).toBe(agentId);
  expect(match![2]).toBe(agentId);
  const account: AccountId = { principal_id: match![2], station_id: match![3] };
  await agentRow.locator(".card-detail-member-mention-button").click();
  const chip = accountRow(card, ".mention-chip", account);
  await expect(chip).toBeVisible({ timeout: 30_000 });
  const composer = card.locator(".chat-input");
  const mention = (await chip.locator(".mention-chip-label").innerText()).trim();
  expect(mention).toMatch(/^@/);
  await expect(composer).toHaveValue(`${mention} `);
  // Keep the actual picker insertion so the composer retains the structured
  // mention; a controller/slug string is ordinary text under v1.
  await composer.fill(`${mention} ${prompt}`);
}


export async function createSidecarSourceCard(
  page: Page,
  realmId: string,
  title: string,
) {
  await page.goto(`/kanban/${realmId}`, { waitUntil: "domcontentloaded" });
  await expect(page.locator(".kanban-panel")).toBeVisible({
    timeout: 120_000,
  });
  let acceptedBoardId: string | undefined;
  let publicationError: unknown;
  let frozenSubmission: string | undefined;
  const boardAcceptance = page.waitForResponse(async response => {
    const outgoing = response.request();
    if (outgoing.method() !== "POST" || new URL(response.url()).pathname !== EVENTS_SUBMIT_PATH) return false;
    const event = eventSubmissions(outgoing.postData()).find(event =>
      event.kind === "ak.space.create" && event.realm_id === realmId
      && (event.payload?.object as Record<string, unknown> | undefined)?.kind === "board");
    if (!event) return false;
    const body = outgoing.postData()!;
    if (frozenSubmission === undefined) frozenSubmission = body;
    expect(body === frozenSubmission, "Board retry retains its original signed submission").toBe(true);
    if (response.status() === 503) {
      const problem = await response.json().catch(() => undefined);
      if (wireErrCode(problem) === "temporarily_unavailable") return false;
    }
    return true;
  }, { timeout: 120_000 }).then(async response => {
    const event = eventSubmissions(response.request().postData()).find(event =>
      event.kind === "ak.space.create" && event.realm_id === realmId)!;
    expect(response.ok(), "the new source Board must have an actual accepted response").toBe(true);
    assertAuthoritySubmitOutcome(await response.json(), event, "Sidecar source Board");
    const id = sdkEventDerivedIds(event).object_id;
    if (!id?.startsWith("ak:space:")) throw new Error("accepted source Board has no derived Space id");
    acceptedBoardId = id;
  });
  void boardAcceptance.catch(error => { publicationError = error; });
  await newBoardTrigger(page).click();
  await prepareBoardTitle(page, title);
  await page.locator(".create-board-space-button").click();
  // The toolbar is visible while the Board is still a local pending create.
  // Wait for its accepted canonical route before composing a child List.
  const acceptedBoardRoute = (url: URL) => acceptedBoardId !== undefined
    && decodeURIComponent(url.pathname) === `/kanban/${realmId}/board/${acceptedBoardId}`;
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    if (publicationError) throw publicationError;
    try {
      await expect(page).toHaveURL(acceptedBoardRoute, {
        timeout: Math.max(1, Math.min(2_000, deadline - Date.now())),
      });
      break;
    } catch {
      if (Date.now() >= deadline) break;
      const picker = boardSwitcher(page);
      if (!(await picker.isVisible())) continue;
      if (await picker.getAttribute("aria-expanded") !== "true") {
        await picker.click({ timeout: Math.max(1, Math.min(3_000, deadline - Date.now())) });
      }
      const retry = page.locator(".board-select-menu-panel")
        .getByRole("button", { name: `${title} (create failed)`, exact: true });
      if (await retry.count() !== 1 || !(await retry.isVisible()) || !(await retry.isEnabled())) continue;
      // Drive the existing same-operation retry only for the observed local
      // pre-authoring encryption transition, never an authority rejection.
      const reason = await retry.getAttribute("title");
      if (!reason?.includes("MLS state is not converged yet: encryption transition")) continue;
      if (Date.now() >= deadline) break;
      await retry.click({ timeout: Math.max(1, Math.min(3_000, deadline - Date.now())) });
    }
  }
  await boardAcceptance;
  await expect(page).toHaveURL(acceptedBoardRoute, { timeout: 1 });
  // The accepted route can converge while the retry picker is open. Close
  // that ordinary product popover before interacting with the Board below it.
  const boardPicker = boardSwitcher(page);
  if (await boardPicker.getAttribute("aria-expanded") === "true") await boardPicker.click();
  await expect(boardPicker).toHaveAttribute("aria-expanded", "false");
  const column = await addBoardList(page, "Work");
  await submitBoardCardDraft(column, title);
  const card = page.locator(".kanban-card").filter({ hasText: title });
  await expect(card).toBeVisible({ timeout: 120_000 });
  await expect(card).not.toHaveClass(/\bis-draft\b/, { timeout: 120_000 });
  await card.click();
  const detail = page.locator(".card-detail-modal");
  await expect(detail).toBeVisible({ timeout: 30_000 });
  return detail;
}


export { eventIdFromMessage } from "./message-evidence";


// Observe authentic sockets from page startup, then suppress live data while
// preserving handshakes, controls and independent HTTP resource reads.
export async function controlPrivateLiveHints(page: Page): Promise<{
  suppress: () => Promise<void>;
  observations: () => { blocked_http_subscriptions: number; observed_websockets: number; dropped_live_frames: number };
  restore: () => Promise<void>;
}> {
  let http = 0;
  let sockets = 0;
  let dropped = 0;
  let active = false;
  const httpMatch = (url: URL) => /\/_arkret\/self\/(account|events|signal)\/subscribe$/.test(url.pathname);
  const socketMatch = (url: URL) => url.pathname.startsWith("/_arkret/");
  const activeHttp = new Set<Request>();
  const started = (request: Request) => {
    if (httpMatch(new URL(request.url()))) activeHttp.add(request);
  };
  const finished = (request: Request) => { activeHttp.delete(request); };
  page.on("request", started);
  page.on("requestfinished", finished);
  page.on("requestfailed", finished);
  const handler = async (route: Route) => {
    if (!active) { await route.fallback(); return; }
    http += 1; await route.abort("connectionfailed");
  };
  await page.route(httpMatch, handler);
  await page.routeWebSocket(socketMatch, route => {
    sockets += 1;
    const server = route.connectToServer();
    server.onMessage(message => {
      if (active) {
        const frame = JSON.parse(message.toString());
        if (frame.kind === "data") { dropped += 1; return; }
      }
      route.send(message);
    });
  });
  return {
    suppress: async () => {
      active = true;
      // Retire any old HTTP subscription; fresh WebSockets keep authentic
      // welcome/open/control traffic and withhold only live data frames.
      await page.context().setOffline(true);
      await page.context().setOffline(false);
      await expect.poll(() => sockets, { timeout: 60_000 }).toBeGreaterThan(0);
      await expect.poll(() => activeHttp.size, { timeout: 30_000,
        message: "all pre-cut HTTP live subscriptions must retire before the private write" }).toBe(0);
    },
    observations: () => ({ blocked_http_subscriptions: http, observed_websockets: sockets, dropped_live_frames: dropped }),
    restore: async () => {
      active = false;
      await page.unroute(httpMatch, handler);
      page.off("request", started);
      page.off("requestfinished", finished);
      page.off("requestfailed", finished);
      activeHttp.clear();
    },
  };
}


export function displayPairingCode(pairingCode: string): string {
  expect(pairingCode).toMatch(/^[0-9]{8}$/);
  return `${pairingCode.slice(0, 4)} ${pairingCode.slice(4)}`;
}
