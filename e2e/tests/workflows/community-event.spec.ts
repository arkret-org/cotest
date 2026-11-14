// A single project carried from browser-owned registration to shared delivery.
// Contract: e2e/scenarios/workflows/community-event.md
import { createHash } from "node:crypto";
import { observeMessageSendAction } from "../../helpers/action-evidence";
import { writeFileSync } from "node:fs";
import { expect, test, type Page, type Locator } from "../../helpers/arkret-test";
import { accountActorId, canonicalJson, assertAuthoritySubmitOutcome, sdkEventDerivedObjectId, wireErrCode } from "../../helpers/coland-api";
import { decodeIngressEvents, type IngressEvent } from "../../helpers/event-ingress";
import { colandServiceId } from "../../helpers/env";
import { newBoardTrigger, addBoardList, fillCardNarrative, filterCardAssignee } from "../../helpers/kanban-product-ui";
import { openRegisteredUserPage } from "../../helpers/users";
import { stepShot } from "../../helpers/screenshots";

test.use({ trace: "off", video: "off", screenshot: "off" });

async function committed(page: Page, kind: string, realmId: string, action: () => Promise<unknown>): Promise<IngressEvent> {
  const response = page.waitForResponse(response => {
    const request = response.request();
    return request.method() === "POST" && new URL(request.url()).pathname === "/_arkret/self/events"
      && decodeIngressEvents(request.postData()).some(event => event.kind === kind && event.realm_id === realmId);
  }, { timeout: 120_000 });
  const [accepted] = await Promise.all([response, action()]);
  const outcome = await accepted.json();
  expect(accepted.status(), `${kind} admission succeeds; refusal=${wireErrCode(outcome) || "none"}`).toBe(200);
  const event = decodeIngressEvents(accepted.request().postData()).find(event => event.kind === kind && event.realm_id === realmId)!;
  expect(outcome.status, `${kind} commits at the authority`).toBe("committed");
  assertAuthoritySubmitOutcome(outcome, event, `community project ${kind}`);
  return event;
}

async function assertAssigned(page: Page, principalId: string): Promise<void> {
  const detail = page.locator(".card-detail-modal");
  await expect(detail.locator(".assignee-chip-label")).toHaveCount(1);
  await detail.locator(".card-detail-assignee-add").click();
  const option = await filterCardAssignee(page, canonicalJson(accountActorId(principalId)));
  await expect(option).toHaveAttribute("aria-pressed", "true");
  await detail.locator(".card-detail-assignee-cancel").click();
}

async function closeProjectCard(page: Page, boardPath: string): Promise<void> {
  const detail = page.locator(".card-detail-modal");
  await detail.locator(".card-detail-close-button").click();
  await expect(detail).toHaveCount(0);
  await expect(page).toHaveURL(url => url.pathname === boardPath);
}

// Retry only a UI activation that has not handed off its exact draft. The
// product clears this field synchronously when it enqueues the original.
async function submitProjectCard(column: Locator, title: string): Promise<void> {
  const input = column.locator(".new-card-title-input");
  if (!(await input.isVisible())) await column.locator(".add-card-button").click();
  await input.fill(title);
  await expect(input).toHaveValue(title);
  await expect(column.locator(".board-card-composer .input-empty-prompt")).toHaveCount(0);
  let activated = false;
  await expect(async () => {
    const value = await input.inputValue();
    if (value === "") {
      expect(activated, "the exact card draft clears only after its submission handoff").toBe(true);
      return;
    }
    expect(value).toBe(title);
    const submit = column.locator(".save-card-button");
    await expect(submit).toBeEnabled({ timeout: 3_000 });
    await submit.click({ timeout: 3_000 });
    activated = true;
    await expect(input).toHaveValue("", { timeout: 1_000 });
  }).toPass({ timeout: 90_000, intervals: [250, 500, 1_000] });
}

async function submitProjectBoard(page: Page, title: string): Promise<void> {
  const form = page.locator(".board-create-popover");
  const input = form.locator(".new-board-title-input input, .new-board-title-input textarea");
  await input.fill(title);
  await expect(input).toHaveValue(title);
  await expect(form.locator(".input-empty-prompt")).toHaveCount(0);
  let activated = false;
  await expect(async () => {
    if (await form.count() === 0) {
      expect(activated, "the Board draft closes only after its submission handoff").toBe(true);
      return;
    }
    await expect(input).toHaveValue(title);
    const submit = form.locator(".create-board-space-button");
    await expect(submit).toBeEnabled({ timeout: 3_000 });
    await submit.click({ timeout: 3_000 });
    activated = true;
    await expect(form).toHaveCount(0, { timeout: 1_000 });
  }).toPass({ timeout: 90_000, intervals: [250, 500, 1_000] });
}

test("three browser-owned members deliver a community event through encrypted discussion, assigned cards and an attachment @community-event-gate", async ({ browser, request }, testInfo) => {
  test.setTimeout(1_800_000);
  const stamp = Date.now();
  const flows: Array<Awaited<ReturnType<typeof openRegisteredUserPage>>> = [];
  const browserFailures: Array<{ actor: string; type: string; message: string }> = [];
  const requests: Array<{ actor: string; method: string; path: string; status: number }> = [];
  const acceptedCuts = new Map<string, { members: Set<string>; covered: boolean }>();
  const progress: Array<{ phase: string; completed_at: string }> = [];
  let realm: string | undefined;
  let boardPath: string | undefined;
  const checkpoint = (phase: string) => {
    progress.push({ phase, completed_at: new Date().toISOString() });
    writeFileSync(testInfo.outputPath("project-progress.json"), JSON.stringify({ realm, boardPath, progress }, null, 2));
  };
  checkpoint("project attempt started");
  try {
    for (const actor of ["manager", "designer", "volunteer"]) {
      const flow = await openRegisteredUserPage(browser, request, `community-${actor}`);
      flow.page.page.on("pageerror", error => browserFailures.push({ actor, type: "pageerror", message: error.message }));
      flow.page.page.on("console", message => {
        if (message.type() === "error" || ["outbound writer scope", "ordinary Event submission failed", "exact assignee state read failed", "MLS send gate publication mismatch", "MLS send readiness", "kanban submit failed", "MLS coverage repair"].some(text => message.text().includes(text))) browserFailures.push({ actor, type: "console", message: message.text() });
      });
      flow.page.page.on("response", async response => {
        const url = new URL(response.url());
        const path = url.pathname;
        if (path.startsWith("/_arkret/self/")) requests.push({ actor, method: response.request().method(), path, status: response.status() });
        if (actor !== "manager" || path !== "/_arkret/self/realm-state-snapshot/head" || response.status() !== 200) return;
        const snapshot = await response.json().catch(() => undefined);
        const entries = snapshot?.current_state_entries;
        if (!Array.isArray(entries)) return;
        const scopeRealm = url.searchParams.get("realm_id");
        const mls = entries.find(entry => entry.selector?.kind === "mls_group"
          && entry.selector.scope_ref?.kind === "realm" && entry.selector.scope_ref.realm_id === scopeRealm)?.value;
        const members = new Set<string>(entries.filter(entry => entry.selector?.kind === "member_state"
          && entry.value?.membership === "join").map(entry => canonicalJson(entry.selector.actor_id)));
        if (scopeRealm) acceptedCuts.set(scopeRealm, { members, covered: mls !== undefined
          && typeof mls.current_key_access_revision === "string"
          && mls.current_key_access_revision === mls.covered_key_access_revision });
      });
      flows.push(flow);
    }
    const [alice, bob, carol] = flows;
    checkpoint("three independent browser registrations and device identities accepted");
    realm = await alice.page.createRealm({
      title: `Community event ${stamp}`,
      summary: "Alice coordinates the venue, Bob designs the poster, Carol recruits volunteers.",
      joinRule: "invite", mlsActivated: true,
    });
    await alice.page.gotoRealmAdminSection(realm, "access");
    const invitations = alice.page.page.locator(".realm-invite-links");
    await invitations.getByLabel("Maximum different accounts", { exact: true }).fill("2");
    await invitations.getByRole("button", { name: "Prepare invitation", exact: true }).click();
    await expect(invitations.locator(".realm-invite-link-message")).toContainText("prepared locally");
    await invitations.getByRole("button", { name: "Publish / retry same invitation", exact: true }).click();
    const shared = invitations.locator("textarea.realm-invite-link-share");
    await expect(shared).toBeVisible({ timeout: 90_000 });
    await expect.poll(async () => (await shared.inputValue()).includes("lt=invite"), { timeout: 90_000 }).toBe(true);
    const link = await shared.inputValue();
    for (const member of [bob, carol]) {
      await member.page.page.goto("/realms/manage");
      const join = member.page.page.locator(".realm-invite-links");
      await join.getByLabel("Paste invitation link after signing in", { exact: true }).fill(link);
      await join.locator(".realm-invite-link-confirm").click();
      await expect(join.locator(".realm-invite-link-message")).toContainText("Joined. Membership is accepted", { timeout: 120_000 });
      await alice.page.gotoRealmAdminSection(realm, "security");
      await alice.page.page.locator(".advanced-access-toggle").click();
      await alice.page.page.locator(".cap-grant-tag-input input").fill("ak.message.create");
      await alice.page.page.locator(".cap-grant-subject-input input").fill(JSON.stringify({
        principal_id: member.user.id, station_id: colandServiceId(),
      }));
      await alice.page.page.locator(".cap-grant-submit-button").click();
      await expect(alice.page.page.locator(".realm-settings-content > .write-status")).toContainText("Permission granted. Grant ID:", { timeout: 120_000 });
    }
    checkpoint("two invitation uses accepted and explicit message permissions granted");

    // Membership acceptance precedes its covering MLS Commit. Observe the
    // complete accepted cut before authoring the first project ciphertext.
    for (const member of flows) await member.page.gotoTimelineRealm(realm);
    await expect.poll(() => {
      const cut = acceptedCuts.get(realm!);
      return cut?.covered === true && flows.every(member => cut.members.has(canonicalJson(accountActorId(member.user.id))));
    }, { timeout: 120_000, message: "all project memberships must be covered by the accepted MLS cut" }).toBe(true);
    const kickoff = `Project kickoff: venue, poster and volunteers ${stamp}`;
    const finishKickoffAction = await observeMessageSendAction(alice.page.page);
    let kickoffEvent: Awaited<ReturnType<typeof committed>>;
    try {
      kickoffEvent = await committed(alice.page.page, "ak.message.create", realm!, () => alice.page.sendTimelineMessage(realm!, kickoff));
    } finally {
      await finishKickoffAction(testInfo, {
        draft_retained: await alice.page.page.locator(".chat-input").inputValue().catch(() => "") === kickoff,
        message_row_present: await alice.page.page.locator(".chat-message").filter({hasText: kickoff}).count() > 0,
      });
    }
    expect(JSON.stringify(kickoffEvent).includes(kickoff), "kickoff is encrypted on ingress").toBe(false);
    for (const member of flows) await member.page.expectTimelineEventVisible(kickoff, 120_000);
    checkpoint("all accepted memberships covered by MLS and kickoff decrypts for every member");

    const boardTitle = `Event deliverables ${stamp}`;
    const listTitle = `Deliverables ${stamp}`;
    await alice.page.page.goto(`/kanban/${realm}`);
    await expect(alice.page.page.locator(".kanban-panel")).toBeVisible({ timeout: 120_000 });
    await newBoardTrigger(alice.page.page).click();
    await committed(alice.page.page, "ak.space.create", realm!, () => submitProjectBoard(alice.page.page, boardTitle));
    await expect(alice.page.page.locator(".kanban-empty-board")).toContainText("No lists yet", { timeout: 90_000 });
    const column = await addBoardList(alice.page.page, listTitle);
    boardPath = new URL(alice.page.page.url()).pathname;
    const tasks = [
      { title: `Venue booking ${stamp}`, owner: alice, body: `Venue confirmed: community hall, 60 seats. ${stamp}` },
      { title: `Event poster ${stamp}`, owner: bob, body: `Poster approved: doors open at 14:00. ${stamp}` },
      { title: `Volunteer roster ${stamp}`, owner: carol, body: `Six volunteers confirmed for reception and cleanup. ${stamp}` },
    ];
    const assignmentIds = new Map<string, string>();
    const acceptedAssignmentIds = new Set<string>();
    for (const task of tasks) {
      await expect(alice.page.page.locator(".card-detail-modal")).toHaveCount(0);
      await expect(alice.page.page).toHaveURL(url => url.pathname === boardPath);
      await committed(alice.page.page, "ak.strand.create", realm!, () => submitProjectCard(column, task.title));
      const card = column.locator(".kanban-card").filter({ hasText: task.title });
      await expect(card).not.toHaveClass(/\bis-draft\b/, { timeout: 120_000 });
      await card.click();
      const detail = alice.page.page.locator(".card-detail-modal");
      await expect(detail).toBeVisible();
      await detail.locator(".card-detail-edit-description-button").click();
      await fillCardNarrative(alice.page.page, "Description", task.body);
      const update = await committed(alice.page.page, "ak.strand.update", realm!, () => detail.locator(".card-detail-save-button").click());
      expect(JSON.stringify(update).includes(task.body), "private card body is encrypted on ingress").toBe(false);
      await expect(detail.locator(".card-description-panel")).toContainText(task.body, { timeout: 120_000 });
      await detail.locator(".card-detail-assignee-add").click();
      const expectedActor = accountActorId(task.owner.user.id);
      await expect(detail.locator(".assignee-picker-option").first()).toBeVisible({ timeout: 120_000 });
      await testInfo.attach(`assignee-candidates-${task.owner.user.name}`, {
        body: JSON.stringify({ expected_actor: expectedActor, labels: await detail.locator(".assignee-option-label").allTextContents() }),
        contentType: "application/json",
      });
      const option = await filterCardAssignee(alice.page.page, canonicalJson(expectedActor));
      await option.click();
      await expect(option).toHaveAttribute("aria-pressed", "true");
      const assignment = await committed(alice.page.page, "ak.relation.create", realm!, () => detail.locator(".card-detail-assignee-save").click());
      expect(assignment.payload?.relation).toMatchObject({ relation_kind: "assigned_to", to_ref: expectedActor });
      assignmentIds.set(task.title, sdkEventDerivedObjectId(assignment));
      acceptedAssignmentIds.add(sdkEventDerivedObjectId(assignment));
      await assertAssigned(alice.page.page, task.owner.user.id);
      await stepShot(alice.page.page, testInfo, `assigned-deliverable-${tasks.indexOf(task)}`);
      await closeProjectCard(alice.page.page, boardPath!);
      checkpoint(`accepted encrypted deliverable and reopened assignee: ${task.title}`);
    }
    checkpoint("three deliverables accepted with encrypted descriptions and explicit assignees");

    for (const member of flows) {
      await member.page.page.goto(boardPath);
      for (const task of tasks) {
        const card = member.page.page.locator(".kanban-card").filter({ hasText: task.title });
        await expect(card).toBeVisible({ timeout: 120_000 });
        await card.click();
        const detail = member.page.page.locator(".card-detail-modal");
        await expect(detail.locator(".card-description-panel")).toContainText(task.body, { timeout: 120_000 });
        await expect(detail.locator(".card-detail-description-locked")).toHaveCount(0);
        await assertAssigned(member.page.page, task.owner.user.id);
        await closeProjectCard(member.page.page, boardPath!);
      }
    }
    checkpoint("all three members decrypt each deliverable and see its assignee");

    for (const member of flows) await member.page.gotoTimelineRealm(realm);
    for (const [index, author] of flows.entries()) {
      const message = `${tasks[index].body} Delivery accepted by ${author.user.displayName}.`;
      const event = await committed(author.page.page, "ak.message.create", realm!, () => author.page.sendTimelineMessage(realm!, message));
      expect(JSON.stringify(event).includes(message), "project discussion is encrypted on ingress").toBe(false);
      for (const reader of flows) {
        await reader.page.expectTimelineEventVisible(message, 120_000);
        await expect(reader.page.page.locator(".chat-message").filter({ hasText: message })).toHaveCount(1);
      }
    }
    checkpoint("each member publishes a deliverable report received exactly once by every member");

    const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII=", "base64");
    const filename = `approved-poster-${stamp}.png`;
    const file = testInfo.outputPath(filename);
    writeFileSync(file, png);
    const announcement = `Final approved community event poster ${stamp}`;
    const uploadPattern = /\/_arkret\/self\/blob\/upload(?:\?.*)?$/;
    let releaseUpload!: () => void;
    const captionEntered = new Promise<void>(resolve => { releaseUpload = resolve; });
    let uploadStarted = false;
    await bob.page.page.route(uploadPattern, async route => {
      uploadStarted = true;
      await captionEntered;
      await route.continue();
    });
    let attachment: Awaited<ReturnType<typeof committed>>;
    try {
      await bob.page.page.locator(".attachment-menu-button").click();
      const chooser = bob.page.page.waitForEvent("filechooser");
      await bob.page.page.locator("button.attachment-file-picker").click();
      await (await chooser).setFiles(file);
      await expect(bob.page.page.locator(".compose-attachment")).toHaveCount(1, { timeout: 120_000 });
      await expect.poll(() => uploadStarted, { timeout: 120_000 }).toBe(true);
      await bob.page.page.locator(".chat-input").fill(announcement);
      await expect(bob.page.page.locator(".send-chat-button")).toBeDisabled();
      releaseUpload();
      attachment = await committed(bob.page.page, "ak.message.create", realm!, () => bob.page.sendTimelineMessage(realm!, announcement));
    } finally {
      releaseUpload();
      await bob.page.page.unroute(uploadPattern);
    }
    expect(attachment.payload?.blob_refs).toHaveLength(1);
    expect(JSON.stringify(attachment).includes(filename), "private filename is encrypted on ingress").toBe(false);
    for (const reader of flows) {
      await reader.page.expectTimelineEventVisible(announcement, 120_000);
      const image = reader.page.page.getByRole("img", { name: filename, exact: true });
      await expect(image).toBeVisible({ timeout: 120_000 });
      const received = await image.evaluate(async (img: HTMLImageElement) => Array.from(new Uint8Array(await (await fetch(img.src)).arrayBuffer())));
      expect(createHash("sha256").update(Buffer.from(received)).digest("hex")).toBe(createHash("sha256").update(png).digest("hex"));
    }
    checkpoint("designer's encrypted poster attachment decrypts to the exact bytes for all members");
    const presenceNames = await bob.page.page.locator(".presence-name").allTextContents();
    expect(presenceNames.length).toBeGreaterThan(0);
    expect(presenceNames.every(name => !name.trim().startsWith("{"))).toBe(true);
    await stepShot(bob.page.page, testInfo, "encrypted-project-discussion");

    for (const member of flows) {
      await member.page.page.reload({ waitUntil: "domcontentloaded" });
      await member.page.expectTimelineEventVisible(announcement, 120_000);
      await expect(member.page.page.locator(".chat-message").filter({ hasText: announcement })).toHaveCount(1);
      for (const [index, author] of flows.entries()) {
        const report = `${tasks[index].body} Delivery accepted by ${author.user.displayName}.`;
        await member.page.expectTimelineEventVisible(report, 120_000);
        await expect(member.page.page.locator(".chat-message").filter({ hasText: report })).toHaveCount(1);
      }
      const coldImage = member.page.page.getByRole("img", { name: filename, exact: true });
      await expect(coldImage).toBeVisible({ timeout: 120_000 });
      const coldBytes = await coldImage.evaluate(async (img: HTMLImageElement) => Array.from(new Uint8Array(await (await fetch(img.src)).arrayBuffer())));
      expect(createHash("sha256").update(Buffer.from(coldBytes)).digest("hex")).toBe(createHash("sha256").update(png).digest("hex"));
      await member.page.page.goto(boardPath);
      await expect(member.page.page.locator(".board-select-menu-host")).toContainText(boardTitle, { timeout: 120_000 });
      await expect(member.page.page.locator(".kanban-column-title")).toHaveText(listTitle, { timeout: 120_000 });
      for (const task of tasks) {
        await member.page.page.locator(".kanban-card").filter({ hasText: task.title }).click();
        const detail = member.page.page.locator(".card-detail-modal");
        await expect(detail.locator(".card-description-panel")).toContainText(task.body, { timeout: 120_000 });
        await assertAssigned(member.page.page, task.owner.user.id);
        await expect(detail.locator(".card-detail-description-locked")).toHaveCount(0);
        await closeProjectCard(member.page.page, boardPath!);
      }
    }
    checkpoint("all three members retain the accepted discussion and assigned encrypted deliverables after document reload");

    // Hand over an existing assignment, then return it to its original actor.
    // Returning must create a live edge after that actor's prior tombstone.
    const handoverTask = tasks[2];
    let previousOwner = carol;
    for (const nextOwner of [alice, carol]) {
      const page = alice.page.page;
      await page.locator(".kanban-card").filter({ hasText: handoverTask.title }).click();
      const detail = page.locator(".card-detail-modal");
      await assertAssigned(page, previousOwner.user.id);
      await detail.locator(".card-detail-assignee-add").click();
      const option = await filterCardAssignee(page, canonicalJson(accountActorId(previousOwner.user.id)));
      await expect(option).toHaveAttribute("aria-pressed", "true");
      await option.click();
      await expect(option).toHaveAttribute("aria-pressed", "false");
      await filterCardAssignee(page, canonicalJson(accountActorId(nextOwner.user.id)));
      await expect(option).toHaveAttribute("aria-pressed", "false");
      await option.click();
      await expect(option).toHaveAttribute("aria-pressed", "true");
      const commitOrder: string[] = [];
      const [removed, added] = await Promise.all([
        committed(page, "ak.relation.tombstone", realm!, async () => {}).then(event => {
          commitOrder.push("ak.relation.tombstone");
          return event;
        }),
        committed(page, "ak.relation.create", realm!, () => detail.locator(".card-detail-assignee-save").click()).then(event => {
          commitOrder.push("ak.relation.create");
          return event;
        }),
      ]);
      expect(commitOrder).toEqual(["ak.relation.tombstone", "ak.relation.create"]);
      expect(removed.payload?.relation_id).toBe(assignmentIds.get(handoverTask.title));
      expect(added.payload?.relation).toMatchObject({ relation_kind: "assigned_to", to_ref: accountActorId(nextOwner.user.id) });
      const nextRelationId = sdkEventDerivedObjectId(added);
      expect(acceptedAssignmentIds.has(nextRelationId), "a handover never reuses any previously accepted RelationId").toBe(false);
      acceptedAssignmentIds.add(nextRelationId);
      assignmentIds.set(handoverTask.title, nextRelationId);
      await closeProjectCard(page, boardPath!);
      for (const member of flows) {
        await member.page.page.reload({ waitUntil: "domcontentloaded" });
        const card = member.page.page.locator(".kanban-card").filter({ hasText: handoverTask.title });
        await expect(card).toBeVisible({ timeout: 120_000 });
        await card.click();
        const reopened = member.page.page.locator(".card-detail-modal");
        await expect(reopened.locator(".card-description-panel")).toContainText(handoverTask.body, { timeout: 120_000 });
        await assertAssigned(member.page.page, nextOwner.user.id);
        await closeProjectCard(member.page.page, boardPath!);
      }
      checkpoint(`assignment handover accepted and retained by all members: ${previousOwner.user.name} to ${nextOwner.user.name}`);
      previousOwner = nextOwner;
    }
    await stepShot(alice.page.page, testInfo, "delivered-project-board-desktop");
    const mobile = carol.page.page;
    await mobile.setViewportSize({ width: 390, height: 844 });
    await expect(mobile.locator(".kanban-card")).toHaveCount(3);
    await expect(mobile.locator(".board-select-menu-host")).toContainText(boardTitle);
    await expect(mobile.locator(".kanban-column-title")).toHaveText(listTitle);
    await stepShot(mobile, testInfo, "delivered-project-board-mobile");
    await mobile.locator(".kanban-card").last().scrollIntoViewIfNeeded();
    await expect(mobile.locator(".kanban-card").last()).toBeInViewport();
    await stepShot(mobile, testInfo, "mobile-project-board-scroll-end");
    const list = mobile.locator(".workspace-pane-list.is-visible");
    for (const destination of ["realms", "contacts", "agents"]) {
      await mobile.locator(`.rail-${destination}`).click();
      await expect(list).toBeVisible();
      await expect(list).toHaveCSS("animation-name", "none");
      await stepShot(mobile, testInfo, `mobile-${destination}-list`);
    }
    await mobile.locator(".rail-account").click();
    await expect(mobile.locator(".account-page")).toBeVisible();
    await stepShot(mobile, testInfo, "mobile-account");
    await mobile.locator(".account-page-settings").click();
    const backToAccount = mobile.getByRole("button", { name: "Back to account", exact: true });
    const backToList = mobile.getByRole("button", { name: "Back to list", exact: true });
    await expect(backToAccount).toBeInViewport();
    await stepShot(mobile, testInfo, "mobile-settings-list");
    await mobile.locator(".settings-nav-item-theme").click();
    await expect(backToList).toBeInViewport();
    await expect(backToAccount).toBeHidden();
    await stepShot(mobile, testInfo, "mobile-settings-theme");
    await backToList.click();
    await backToAccount.click();
    await expect(mobile).toHaveURL(/\/account$/);
    await mobile.goto("/settings");
    await expect(backToAccount).toBeInViewport();
    await backToAccount.click();
    await expect(mobile).toHaveURL(/\/account$/);
    expect(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    checkpoint("live mobile lists, Settings return paths and direct Settings entry accepted");
  } catch (error) {
    await testInfo.attach("community-runtime-errors", { body: JSON.stringify(browserFailures), contentType: "application/json" });
    await testInfo.attach("community-response-statuses", { body: JSON.stringify(requests), contentType: "application/json" });
    for (const [index, flow] of flows.entries()) {
      const messageBoundary = testInfo.outputPath(`community-message-boundary-${index}.json`);
      writeFileSync(messageBoundary, JSON.stringify(await flow.page.page.evaluate(() => ({
        composer_present: Boolean(document.querySelector(".chat-input")),
        draft_nonempty: Boolean((document.querySelector(".chat-input") as HTMLTextAreaElement | null)?.value),
        send_disabled: (document.querySelector(".send-chat-button") as HTMLButtonElement | null)?.disabled ?? true,
        pending_rows: document.querySelectorAll(".message-send-status").length,
        error_rows: document.querySelectorAll(".chat-message-error").length,
        status: Array.from(document.querySelectorAll(".chat-status,.compose-upload-progress,.composer-send-diagnostic,.chat-message-error,.message-send-status"))
          .map(node => (node.textContent ?? "").slice(0, 500)).slice(0, 20),
      })), null, 2));
      await testInfo.attach(`community-message-boundary-${index}`, { path: messageBoundary, contentType: "application/json" });
      const filterStatePath = testInfo.outputPath(`assignee-filter-state-${index}.json`);
      writeFileSync(filterStatePath, JSON.stringify({
        path: new URL(flow.page.page.url()).pathname,
        filter: await flow.page.page.getByRole("textbox", { name: "Filter members", exact: true }).evaluateAll(nodes => nodes.map(node => ({ value: (node as HTMLInputElement).value, focused: node === document.activeElement, document_focused: document.hasFocus() }))),
        options: await flow.page.page.locator(".assignee-option-label").allTextContents(),
      }, null, 2));
      await testInfo.attach(`assignee-filter-state-${index}`, { path: filterStatePath, contentType: "application/json" });
      await testInfo.attach(`community-ui-state-${index}`, {
        body: JSON.stringify({
          path: new URL(flow.page.page.url()).pathname,
          card_modals: await flow.page.page.locator(".card-detail-modal").count(),
          card_titles: await flow.page.page.locator(".kanban-card-title").allTextContents(),
          composer: await flow.page.page.locator(".new-card-title-input").evaluateAll(nodes => nodes.map(node => ({ value: (node as HTMLTextAreaElement).value, connected: node.isConnected }))),
          empty_prompts: await flow.page.page.locator(".board-card-composer .input-empty-prompt").count(),
          board_draft: await flow.page.page.locator(".board-create-popover input, .board-create-popover textarea").evaluateAll(nodes => nodes.map(node => (node as HTMLInputElement).value)),
          board_status: await flow.page.page.locator(".board-status").allTextContents(),
          attachment_status: await flow.page.page.locator(".compose-upload-progress").allTextContents(),
        }), contentType: "application/json",
      }).catch(() => {});
      await testInfo.attach(`community-write-status-${index}`, {
        body: JSON.stringify(await flow.page.page.locator(".assignee-edit-status, .board-status, .write-status, .kanban-board-status").allTextContents()),
        contentType: "application/json",
      }).catch(() => {});
    }
    throw error;
  } finally {
    await testInfo.attach("community-project-progress", { path: testInfo.outputPath("project-progress.json"), contentType: "application/json" }).catch(() => {});
    await Promise.allSettled(flows.map(flow => flow.page.close()));
  }
});
