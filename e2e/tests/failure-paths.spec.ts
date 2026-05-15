import { expect, test, type Route } from "@playwright/test";
import { stepShot } from "../helpers/screenshots";
import { ensureRegistered, issueDevSession, openUserPage, uniqueUser } from "../helpers/users";

test.describe.configure({ mode: "serial" });

test("chat send 5xx surfaces chat-message-error, retry recovers when the route is cleared", async ({
  browser,
  request,
}, testInfo) => {
  const user = uniqueUser("chat-failure");
  await ensureRegistered(request, user);
  const token = await issueDevSession(request, user);
  const actor = await openUserPage(browser, user, token);
  const stamp = Date.now();
  const title = `Chat Failure Space ${stamp}`;
  const body = `chat retry payload ${stamp}`;

  try {
    const spaceId = await actor.createSpace({
      title,
      summary: "failure path coverage",
      discoverability: "public",
    });

    await actor.page.goto(`/chat/${spaceId}`, { waitUntil: "domcontentloaded" });
    await expect(actor.page.getByTestId("chat-panel")).toBeVisible({ timeout: 120_000 });
    await expect(actor.page.getByTestId("chat-composer")).toBeVisible();

    let blockSend = true;
    await actor.page.route("**/api/v1/events", async (route: Route) => {
      if (blockSend && route.request().method() === "POST") {
        await fulfillJson(route, 500, {
          ok: false,
          error: { code: "e2e_simulated_5xx", message: "simulated upstream failure" },
        });
        return;
      }
      await route.continue();
    });

    await actor.page.getByTestId("chat-input").fill(body);
    await actor.page.getByTestId("send-chat-button").click();
    const failed = actor.page.getByTestId("chat-message").filter({ hasText: body }).first();
    await expect(failed).toBeVisible({ timeout: 30_000 });
    await expect(failed.getByTestId("chat-message-error")).toBeVisible({ timeout: 30_000 });
    await expect(failed.getByTestId("chat-retry-button")).toBeVisible();
    await expect(actor.page.getByTestId("chat-status")).toContainText(/Message send failed/i);
    await stepShot(actor.page, testInfo, "01-send-failed");

    blockSend = false;
    await failed.getByTestId("chat-retry-button").click();
    await expect(failed.getByTestId("chat-message-error")).toBeHidden({ timeout: 30_000 });
    await expect(actor.page.getByTestId("chat-status")).toContainText(/Message sent|persisted|retried/i);
    await stepShot(actor.page, testInfo, "02-retry-succeeded");
  } finally {
    await actor.page.unrouteAll().catch(() => {});
    await actor.close();
  }
});

async function fulfillJson(route: Route, status: number, body: unknown) {
  await route.fulfill({
    status,
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
      "access-control-allow-headers":
        "authorization,content-type,idempotency-key,x-contrix-request-id,x-contrix-wait-for",
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}
