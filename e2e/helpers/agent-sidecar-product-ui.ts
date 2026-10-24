// Shared product UI actions; no session or protocol outcome is injected.
import { expect, type Page, type Route, type Request, type TestInfo, type Locator } from './arkret-test';
import { assertAuthoritySubmitOutcome, wireErrCode } from './coland-api';
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


export async function startSavfoxPairing(
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


export async function saveSavfoxChannel(savfox: Page): Promise<void> {
  await savfox
    .getByRole("button", { name: "Save changes", exact: true })
    .click();
  await expect(
    savfox.getByRole("heading", { name: "Configure Arkret" }),
  ).toHaveCount(0, { timeout: 120_000 });
}


export async function provisionAgent(
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
  const pairingDeadline = Date.now() + 180_000;
  const remainingPairingBudget = () => Math.max(1, pairingDeadline - Date.now());
  await expect(
    inkson.locator(
      `[data-testid="agent-admin-row"][data-agent-id=${JSON.stringify(body.agent_id)}]`,
    ),
  ).toHaveAttribute("aria-pressed", "true", { timeout: remainingPairingBudget() });
  await expect(inkson.getByTestId("agent-admin-slug-title")).toHaveText(agentSlug, {
    timeout: remainingPairingBudget(),
  });
  await expect(inkson.getByTestId("agent-admin-pairing-card")).toBeVisible({
    timeout: remainingPairingBudget(),
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


export async function pairManagedSavfoxAgent(
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


export async function addAgentToRealm(
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
    await available.getByTestId("confirm-add-agent-to-realm").click();
    const joinResponse = await submittedJoin;
    const joinOutcome = await joinResponse.json() as Record<string, unknown>;
    expect(joinResponse.ok(), `Agent join HTTP ${joinResponse.status()}: ${String(joinOutcome.detail ?? "missing Problem detail")}`)
      .toBe(true);
    const join = eventSubmissions(joinResponse.request().postData()).find(isTargetJoin)!;
    assertAuthoritySubmitOutcome(joinOutcome, join, "normal controller-authored Agent first join");
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


export async function createSidecarSourceCard(
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
  const acceptedBoardRoute = (url: URL) => decodeURIComponent(url.pathname)
    .startsWith(`/kanban/${realmId}/board/ak:space:`);
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    try {
      await expect(page).toHaveURL(acceptedBoardRoute, {
        timeout: Math.max(1, Math.min(2_000, deadline - Date.now())),
      });
      break;
    } catch {
      if (Date.now() >= deadline) break;
      const picker = page.getByTestId("board-space-select-button");
      if (!(await picker.isVisible())) continue;
      if (await picker.getAttribute("aria-expanded") !== "true") {
        await picker.click({ timeout: Math.max(1, Math.min(3_000, deadline - Date.now())) });
      }
      const retry = page.getByRole("option", { name: `${title} (create failed)`, exact: true });
      if (await retry.count() !== 1 || !(await retry.isVisible()) || !(await retry.isEnabled())) continue;
      // Drive the existing same-operation retry only for the observed local
      // pre-authoring encryption transition, never an authority rejection.
      const reason = await retry.getAttribute("title");
      if (!reason?.includes("MLS state is not converged yet: encryption transition")) continue;
      if (Date.now() >= deadline) break;
      await retry.click({ timeout: Math.max(1, Math.min(3_000, deadline - Date.now())) });
    }
  }
  await expect(page).toHaveURL(acceptedBoardRoute, { timeout: 1 });
  // The accepted route can converge while the retry picker is open. Close
  // that ordinary product popover before interacting with the Board below it.
  const boardPicker = page.getByTestId("board-space-select-button");
  if (await boardPicker.getAttribute("aria-expanded") === "true") await boardPicker.click();
  await expect(page.locator(".board-popover-scrim")).toHaveCount(0);
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
  await expect(card).toHaveAttribute("data-card-draft", "false", { timeout: 120_000 });
  await card.click();
  const detail = page.getByTestId("card-detail-modal");
  await expect(detail).toBeVisible({ timeout: 30_000 });
  return detail;
}


export async function eventIdFromMessage(message: ReturnType<Page["getByTestId"]>) {
  return message.evaluate((element) => {
    const candidates = [
      element.getAttribute("data-event-id"),
      element.id.replace(/^chat-msg-/, ""),
      element.querySelector("[data-event-id]")?.getAttribute("data-event-id"),
    ];
    return candidates.find((value) => value?.startsWith("ak:event:")) ?? "";
  });
}


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
