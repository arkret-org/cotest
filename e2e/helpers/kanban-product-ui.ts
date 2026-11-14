import { expect, type Locator, type Page, type Response } from "@playwright/test";
import { assertAuthoritySubmitOutcome, sdkEventDerivedIds, wireErrCode } from "./coland-api";
import { decodeEventIngressBody, ingressEvents } from "./event-ingress";

export function newBoardTrigger(page: Page): Locator {
  return page.locator(".board-popover-host").getByRole("button", { name: "New board", exact: true });
}

export async function openBoardOptions(page: Page, options?: { timeout?: number }): Promise<void> {
  const disclosure = page.locator(".board-toolbar-options > .sapid-collapsible-trigger");
  if (await disclosure.count() && await disclosure.getAttribute("aria-expanded") !== "true") {
    await disclosure.click(options);
  }
}

export async function openNewBoard(page: Page, options?: { timeout?: number }): Promise<void> {
  await openBoardOptions(page, options);
  await newBoardTrigger(page).click(options);
}

export function boardSwitcher(page: Page): Locator {
  return page.locator(".board-select-menu-host").getByRole("button", { name: "Switch board", exact: true });
}

/** Open the actual member tab for the selected card. */
export async function openCardMembers(detail: Locator): Promise<void> {
  const sidebar = detail.locator(".card-detail-sidebar");
  await expect(sidebar).toBeAttached({ timeout: 120_000 });
  if (!await sidebar.isVisible()) {
    await detail.getByRole("button", { name: "Show details", exact: true }).click();
  }
  const members = sidebar.getByRole("tab", { name: /^Members \(\d+\)$/ });
  if (await members.getAttribute("aria-selected") !== "true") await members.click();
  await expect(members).toHaveAttribute("aria-selected", "true");
}

/** Observe the bound empty-title validation before preparing the original intent. */
export async function prepareBoardTitle(page: Page, title: string, timeout = 120_000): Promise<void> {
  const draft = page.locator(".board-create-popover .new-board-title-input :is(input,textarea)");
  await expect(async () => {
    await draft.fill("", { timeout: 3_000 });
    await page.locator(".create-board-space-button").click({ timeout: 3_000 });
    await expect(page.locator(".board-status")).toHaveText("board title is required", { timeout: 1_000 });
  }).toPass({ timeout, intervals: [250, 500, 1_000] });
  await draft.fill(title, { timeout });
  await expect(draft).toHaveValue(title, { timeout });
}

/** Submit the retained local Card draft until its ordinary queue handoff. */
export async function submitBoardCardDraft(column: Locator, title: string): Promise<void> {
  await column.page().bringToFront();
  const input = column.locator(".new-card-title-input");
  await expect(async () => {
    if (!await input.isVisible()) await column.locator(".add-card-button").click({ timeout: 3_000 });
    await input.fill(title, { timeout: 3_000 });
    await expect(input).toHaveValue(title, { timeout: 1_000 });
  }).toPass({ timeout: 30_000, intervals: [250, 500, 1_000] });
  let activated = false;
  await expect(async () => {
    const value = await input.inputValue();
    if (value === "") {
      expect(activated, "the Card draft clears after its original queue handoff").toBe(true);
      return;
    }
    expect(value, "retain the exact Card draft until enqueueing").toBe(title);
    await column.locator(".save-card-button").click({ timeout: 3_000 });
    activated = true;
    await expect(input).toHaveValue("", { timeout: 1_000 });
  }).toPass({ timeout: 30_000, intervals: [250, 500, 1_000] });
}

/** Prepare a local member filter without selecting or submitting anything. */
export async function filterCardAssignee(page: Page, actorId: string): Promise<Locator> {
  await page.bringToFront();
  const detail = page.locator(".card-detail-modal");
  const filter = detail.getByRole("textbox", { name: "Filter members", exact: true });
  const option = detail.locator(".assignee-picker-option");
  await expect(async () => {
    // A pending card refresh can replace the controls during an input event.
    // Reapply only this local query, then inspect the current controls.
    await filter.click({ timeout: 1_000 });
    await filter.fill("", { timeout: 1_000 });
    await filter.fill(actorId, { timeout: 1_000 });
    await expect(filter).toHaveValue(actorId, { timeout: 1_000 });
    await expect(option).toHaveCount(1, { timeout: 1_000 });
  }).toPass({ timeout: 10_000, intervals: [100, 250] });
  return option;
}

export async function fillCardNarrative(
  page: Page,
  name: "Description" | "Synthesis",
  value: string,
): Promise<void> {
  const form = page.locator(".card-detail-edit-form");
  const editor = form.getByRole("textbox", { name, exact: true });
  await page.bringToFront();
  await expect(editor).toBeVisible({ timeout: 45_000 });
  await editor.click();
  await editor.fill(value);
  await expect(form.locator(".card-rich-editor-preview")).toHaveText(value);
  await expect(form.locator(".card-detail-save-button")).toBeEnabled({ timeout: 45_000 });
}

/** Author one List through the accepted Board's ordinary product composer. */
export async function addBoardList(page: Page, title: string): Promise<Locator> {
  await expect(page).toHaveURL(url => /^\/kanban\/ak:realm:[^/]+\/board\/ak:space:[^/]+$/
    .test(decodeURIComponent(url.pathname)), { timeout: 120_000 });
  const [, , realmId, , boardId] = decodeURIComponent(new URL(page.url()).pathname).split("/");
  const composer = page.locator(".board-list-compose");
  const disclosure = page.locator(".board-toolbar-add-list > .sapid-collapsible-trigger");
  if (await disclosure.getAttribute("aria-expanded") !== "true") await disclosure.click();
  const input = composer.locator(".new-column-input");
  const submit = composer.locator(".add-column-button");
  await expect(composer).toBeVisible();
  await expect(submit).toBeEnabled({ timeout: 120_000 });
  await input.fill(title);
  await expect(input).toHaveValue(title);
  await expect(composer.locator(".input-empty-prompt")).toHaveCount(0);
  const listEvent = (response: Response) => {
    const request = response.request();
    if (request.method() !== "POST" || new URL(request.url()).pathname !== "/_arkret/self/events") return undefined;
    return ingressEvents(decodeEventIngressBody(request.postDataJSON())).find(event =>
      event.kind === "ak.space.create" && event.realm_id === realmId
      && (event.payload?.object as Record<string, unknown> | undefined)?.kind === "list");
  };
  let frozenSubmission: string | undefined;
  const acceptance = page.waitForResponse(async response => {
    const event = listEvent(response);
    if (!event) return false;
    const object = event.payload?.object as Record<string, unknown>;
    expect(object.parent_space_id === boardId, "the new List must belong to the selected accepted Board").toBe(true);
    const body = response.request().postData()!;
    if (frozenSubmission === undefined) frozenSubmission = body;
    expect(body === frozenSubmission, "List retry retains its original signed submission").toBe(true);
    if (response.status() === 503) {
      const problem = await response.json().catch(() => undefined);
      if (wireErrCode(problem) === "temporarily_unavailable") return false;
    }
    return true;
  }, { timeout: 120_000 });
  void acceptance.catch(() => {});
  let activated = false;
  await expect(async () => {
    const value = await input.inputValue();
    if (value === "") {
      expect(activated, "the List draft clears only after the ordinary submission handoff").toBe(true);
      return;
    }
    expect(value, "retain the exact List intent until enqueueing its original").toBe(title);
    await expect(submit).toBeEnabled({ timeout: 3_000 });
    await submit.click({ timeout: 3_000 });
    activated = true;
    await expect(input).toHaveValue("", { timeout: 1_000 });
  }).toPass({ timeout: 90_000, intervals: [250, 500, 1_000] });
  const response = await acceptance;
  const event = listEvent(response)!;
  expect(response.ok(), "the new List must have an actual accepted response").toBe(true);
  assertAuthoritySubmitOutcome(await response.json(), event, "Board List create");
  const listId = sdkEventDerivedIds(event).object_id;
  expect(listId?.startsWith("ak:space:"), "the accepted List supplies its derived Space id").toBe(true);
  const column = page.locator(".kanban-column").filter({
    has: page.getByRole("button", { name: `${title} (${listId})`, exact: true }),
  });
  await expect(column).toHaveCount(1, { timeout: 120_000 });
  await expect(column).toBeVisible();
  return column;
}
