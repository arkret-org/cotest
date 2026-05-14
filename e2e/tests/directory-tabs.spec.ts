import { expect, test } from "@playwright/test";
import { stepShot } from "../helpers/screenshots";
import { ensureRegistered, issueDevSession, openUserPage, uniqueUser } from "../helpers/users";

test.describe.configure({ mode: "serial" });

const tabs: Array<{ tab: string; label: string }> = [
  { tab: "tab-objects", label: "objects" },
  { tab: "tab-spaces", label: "spaces" },
  { tab: "tab-organizations", label: "organizations" },
  { tab: "tab-actors", label: "actors" },
  { tab: "tab-handles", label: "handles" },
];

test("directory panel exposes the four-axis banner, contact tools, and all five discovery tabs", async ({
  browser,
  request,
}, testInfo) => {
  const user = uniqueUser("directory");
  await ensureRegistered(request, user);
  const token = await issueDevSession(request, user);
  const actor = await openUserPage(browser, user, token);

  try {
    await actor.gotoDirectory();
    await expect(actor.page.getByTestId("directory-three-axes-banner")).toBeVisible();
    await expect(actor.page.getByTestId("directory-surface-map")).toBeVisible();
    await expect(actor.page.getByTestId("directory-contact-tools")).toBeVisible();
    await expect(actor.page.getByTestId("contact-target-did-input")).toBeVisible();
    await expect(actor.page.getByTestId("contact-requester-did-input")).toBeVisible();
    await stepShot(actor.page, testInfo, "01-directory-axes-banner");

    for (const { tab, label } of tabs) {
      const button = actor.page.getByTestId(tab);
      await button.click();
      await expect(button).toHaveAttribute("aria-selected", "true");
      await expect(button).toHaveClass(/primary/);
      await stepShot(actor.page, testInfo, `02-${label}-active`);
    }

    await actor.page.getByTestId("tab-actors").click();
    await actor.page.getByTestId("directory-search-input").fill(user.handle);
    await actor.page.getByTestId("directory-search-button").click();
    await expect(actor.page.getByTestId("directory-panel")).toContainText(/No actors found|actor-result/);
    await stepShot(actor.page, testInfo, "03-actors-search-empty");
  } finally {
    await actor.close();
  }
});
