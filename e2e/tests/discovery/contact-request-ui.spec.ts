import { expect, test } from "../../helpers/arkret-test";
import { openRegisteredUserPage } from "../../helpers/users";

test("cold requester signs a real locator Contact request through the UI @fully-implemented", async ({ browser, request }) => {
  test.setTimeout(600_000);
  const stamp = Date.now();
  const flows: Array<Awaited<ReturnType<typeof openRegisteredUserPage>>> = [];
  try {
    const alice = await openRegisteredUserPage(browser, request, `contact-ui-alice-${stamp}`);
    flows.push(alice);
    const bob = await openRegisteredUserPage(browser, request, `contact-ui-bob-${stamp}`);
    flows.push(bob);
    await bob.page.page.goto("/settings/account");
    await bob.page.page.getByTestId("settings-invite-locator-refresh").click();
    const locator = bob.page.page.getByTestId("settings-invite-locator-url");
    await expect(locator).toBeVisible({ timeout: 60_000 });
    const address = await locator.inputValue();
    expect(address.includes("#token="), "real locator is available").toBe(true);
    await alice.page.page.goto("/contacts");
    await alice.page.page.reload({ waitUntil: "domcontentloaded" });
    await alice.page.page.getByTestId("add-contact-button").click();
    const form = alice.page.page.getByTestId("contact-request-panel");
    const target = form.getByTestId("contact-target-input");
    await target.fill(address);
    await form.getByTestId("contact-message-input").fill("Please coordinate the project artwork with me.");
    const committed = alice.page.page.waitForResponse(response => {
      if (!new URL(response.url()).pathname.endsWith("/_arkret/self/contacts/request") || response.request().method() !== "POST") return false;
      return response.request().postDataJSON()?.phase === "commit";
    }, { timeout: 90_000 });
    await form.getByTestId("send-contact-request-button").click();
    const requested = await committed;
    expect(requested.status(), "the original signed Contact commit is accepted").toBe(200);
    expect((await requested.json()).status).toBe("accepted");
    await expect(alice.page.page.getByTestId("add-contact-modal")).toBeHidden({ timeout: 60_000 });
    await bob.page.page.goto("/contacts");
    const incoming = bob.page.page.locator('[data-testid^="contact-accept-"]');
    await expect(incoming).toHaveCount(1, { timeout: 90_000 });
    const preparedResponse = bob.page.page.waitForResponse(response =>
      new URL(response.url()).pathname.endsWith("/_arkret/self/contacts/respond")
      && response.request().method() === "POST", { timeout: 60_000 });
    await incoming.click();
    const prepared = await preparedResponse;
    expect(prepared.status()).toBe(200);
    expect(await prepared.json()).toMatchObject({ status: "prepared", operation_kind: "response" });
    await expect(bob.page.page.locator('[data-testid^="contact-message-"]')).toHaveCount(1, { timeout: 90_000 });
    await alice.page.page.reload({ waitUntil: "domcontentloaded" });
    await expect(alice.page.page.locator('[data-testid^="contact-message-"]')).toHaveCount(1, { timeout: 90_000 });
  } finally {
    await Promise.all(flows.map(flow => flow.page.close()));
  }
});

test("Contact address instructions advertise only supported inputs @fully-implemented", async ({ browser, request }) => {
  test.setTimeout(300_000);
  const flow = await openRegisteredUserPage(browser, request, `contact-address-hint-${Date.now()}`);
  try {
    await flow.page.page.goto("/contacts");
    await flow.page.page.getByTestId("add-contact-button").click();
    const form = flow.page.page.getByTestId("contact-request-panel");
    await expect(form).toContainText(/invite link.*complete account/i);
    await expect(form.getByTestId("contact-target-input")).not.toHaveAttribute("placeholder", /alice:|handle/i);
  } finally { await flow.page.close(); }
});
