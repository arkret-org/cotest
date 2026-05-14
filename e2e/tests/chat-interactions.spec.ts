import { expect, test, type Page } from "@playwright/test";
import { stepShot } from "../helpers/screenshots";
import { ensureRegistered, issueDevSession, openUserPage, uniqueUser } from "../helpers/users";

test.describe.configure({ mode: "serial" });

test("chat panel exposes reactions and reply composer transitions", async ({
  browser,
  request,
}, testInfo) => {
  const owner = uniqueUser("chat-owner");
  const member = uniqueUser("chat-member");
  await ensureRegistered(request, owner);
  await ensureRegistered(request, member);
  const token = await issueDevSession(request, owner);
  const actor = await openUserPage(browser, owner, token);
  const stamp = Date.now();
  const title = `Chat Interactions Space ${stamp}`;
  const first = `chat hello ${stamp}`;
  const reply = `replying to ${stamp}`;

  try {
    await actor.gotoProduct();
    const spaceFlow = actor.page.getByTestId("space-lifecycle-flow").first();
    await spaceFlow.getByTestId("space-title-input").fill(title);
    await spaceFlow.getByTestId("space-summary-input").fill("chat interactions coverage");
    await spaceFlow.getByTestId("space-discoverability-input").fill("public");
    await spaceFlow.getByTestId("member-did-input").fill(member.did);
    await spaceFlow.getByTestId("create-space-button").click();
    await expect(spaceFlow).toContainText(/created cx:space:/);
    const spaceId = await extractCreatedSpaceId(actor.page);

    await actor.page.goto(`/chat/${spaceId}`, { waitUntil: "domcontentloaded" });
    await expect(actor.page.getByTestId("chat-panel")).toBeVisible({ timeout: 120_000 });
    await expect(actor.page.getByTestId("chat-composer")).toBeVisible();
    await stepShot(actor.page, testInfo, "01-chat-panel-loaded");

    await actor.page.getByTestId("chat-input").fill(first);
    await actor.page.getByTestId("send-chat-button").click();
    const message = actor.page.getByTestId("chat-message").filter({ hasText: first }).first();
    await expect(message).toBeVisible({ timeout: 30_000 });
    await stepShot(actor.page, testInfo, "02-chat-message-sent");

    await message.getByTestId("chat-react-button").click();
    const picker = actor.page.getByTestId("chat-reaction-picker");
    await expect(picker).toBeVisible();
    await stepShot(actor.page, testInfo, "03-reaction-picker-open");
    await picker.getByRole("button").first().click();
    await expect(picker).toBeHidden();
    await expect(message.getByTestId("chat-reactions")).toBeVisible({ timeout: 30_000 });
    await stepShot(actor.page, testInfo, "04-reaction-rendered");

    await message.getByTestId("chat-reply-button").click();
    await expect(actor.page.getByTestId("chat-reply-banner")).toBeVisible();
    await stepShot(actor.page, testInfo, "05-reply-banner-open");

    await actor.page.getByTestId("chat-input").fill(reply);
    await actor.page.getByTestId("send-chat-button").click();
    const replied = actor.page.getByTestId("chat-message").filter({ hasText: reply }).first();
    await expect(replied).toBeVisible({ timeout: 30_000 });
    await expect(replied.getByTestId("chat-reply-indicator")).toBeVisible();
    await expect(actor.page.getByTestId("chat-reply-banner")).toBeHidden();
    await stepShot(actor.page, testInfo, "06-reply-sent");
  } finally {
    await actor.close();
  }
});

async function extractCreatedSpaceId(page: Page): Promise<string> {
  const text = await page.getByTestId("space-lifecycle-flow").first().innerText();
  const match = text.match(/created (cx:space:[^\s]+)/);
  expect(match, `created space id in: ${text}`).not.toBeNull();
  return match![1];
}
