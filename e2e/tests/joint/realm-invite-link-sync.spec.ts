import { expect, test } from "../../helpers/arkret-test";
import { assertJointStackNotRequired, openDpopUserPage } from "../../helpers/users";

for (const encrypted of [false, true]) {
  test(`share-link members keep synchronizing messages and leave after reload; MLS=${encrypted} @fully-implemented`, async ({ browser, request }) => {
    test.setTimeout(600_000);
    const stamp = Date.now();
    const flows = [];
    for (const actor of ["alice", "bob", "carol"]) {
      const flow = await openDpopUserPage(browser, request, `link-sync-${actor}-${stamp}`);
      if (!flow) {
        await Promise.all(flows.map(value => value.page.close()));
        assertJointStackNotRequired("share-link client current installation");
        test.skip(true, "three real DPoP accounts are required");
        return;
      }
      flows.push(flow);
    }
    const [alice, bob, carol] = flows;
    try {
      const realm = await alice.page.createRealm({ title: `Link collaboration ${stamp}`, mlsActivated: encrypted });
      await alice.page.gotoRealmAdminSection(realm, "access");
      const panel = alice.page.page.getByTestId("realm-invite-links");
      await panel.getByLabel("Maximum different accounts", { exact: true }).fill("2");
      await panel.getByRole("button", { name: "Prepare invitation", exact: true }).click();
      await expect(panel.getByRole("status")).toContainText("prepared locally", { timeout: 60_000 });
      await panel.getByRole("button", { name: "Publish / retry same invitation", exact: true }).click();
      const shared = panel.getByRole("textbox", { name: "Share invitation link", exact: true });
      await expect(shared).toBeVisible({ timeout: 90_000 });
      const link = await shared.inputValue();
      expect(link.includes("lt=invite"), "authority accepted the private share link").toBe(true);
      for (const member of [bob, carol]) {
        await member.page.page.goto("/realms/manage");
        const join = member.page.page.getByTestId("realm-invite-links");
        await join.getByTestId("realm-invite-link-input").fill(link);
        await join.getByTestId("realm-invite-link-confirm").click();
        await expect(join.getByRole("status")).toContainText("Joined. Membership is accepted", { timeout: 120_000 });
      }
      for (const flow of flows) {
        await flow.page.page.goto(`/chat/${realm}`);
        await flow.page.page.reload({ waitUntil: "domcontentloaded" });
        await expect(flow.page.page.getByTestId("chat-input")).toBeVisible({ timeout: 90_000 });
      }
      for (const author of flows) {
        const body = `Accepted shared message ${author.user.name} ${stamp}`;
        const page = author.page.page;
        await expect(page.getByTestId("send-chat-button")).toBeEnabled({ timeout: 120_000 });
        await page.getByTestId("chat-input").fill(body);
        await page.getByTestId("send-chat-button").click();
        const own = page.getByTestId("chat-message").filter({ hasText: body });
        await expect(own).toHaveCount(1, { timeout: 60_000 });
        await expect(own.getByTestId("message-send-status")).toHaveCount(0, { timeout: 90_000 });
        for (const reader of flows) await expect(reader.page.page.getByText(body, { exact: true })).toBeVisible({ timeout: 90_000 });
      }
      await bob.page.gotoRealmAdminSection(realm, "repair");
      await bob.page.page.getByTestId("leave-realm-button").click();
      await bob.page.page.getByTestId("leave-realm-confirm-button").click();
      await expect(bob.page.page.getByTestId("realm-admin-status")).toContainText(/^left /, { timeout: 90_000 });
      for (const member of [alice, carol]) {
        await member.page.page.goto(`/realms/${realm}/members`);
        await member.page.page.reload({ waitUntil: "domcontentloaded" });
        await expect(member.page.page.getByTestId("realm-members-count")).toHaveText("2", { timeout: 90_000 });
      }
    } finally { await Promise.all(flows.map(flow => flow.page.close())); }
  });
}
