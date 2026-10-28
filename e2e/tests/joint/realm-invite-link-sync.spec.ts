import { expect, test } from "../../helpers/arkret-test";
import { openRegisteredUserPage } from "../../helpers/users";
import { colandServiceId } from "../../helpers/env";

for (const encrypted of [false, true]) {
  test(`share-link members keep synchronizing messages and leave after reload; MLS=${encrypted} @fully-implemented`, async ({ browser, request }) => {
    test.setTimeout(1_200_000);
    const stamp = Date.now();
    const flows: Array<Awaited<ReturnType<typeof openRegisteredUserPage>>> = [];
    try {
      for (const actor of ["alice", "bob", "carol"]) {
        flows.push(await openRegisteredUserPage(browser, request, `link-sync-${actor}-${stamp}`));
      }
      const [alice, bob, carol] = flows;
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
      // realm-invite-links.md: joining grants no message-writing capability.
      for (const member of [bob, carol]) {
        await alice.page.gotoRealmAdminSection(realm, "security");
        await alice.page.page.getByTestId("advanced-access-toggle").click();
        await alice.page.page.getByTestId("cap-grant-tag-input").fill("ak.message.create");
        await alice.page.page.getByTestId("cap-grant-subject-input").fill(JSON.stringify({
          principal_id: member.user.id, station_id: colandServiceId(),
        }));
        await expect(alice.page.page.getByTestId("cap-grant-submit-button")).toBeEnabled({ timeout: 60_000 });
        await alice.page.page.getByTestId("cap-grant-submit-button").click();
        await expect(alice.page.page.getByTestId("realm-admin-status")).toContainText("Permission granted. Grant ID:", { timeout: 120_000 });
      }
      for (const flow of flows) {
        await flow.page.page.goto(`/chat/${realm}`);
        await flow.page.page.reload({ waitUntil: "domcontentloaded" });
        await expect(flow.page.page.getByTestId("chat-input")).toBeVisible({ timeout: 90_000 });
        await expect(flow.page.page.getByTestId("status-label")).toHaveText(/^Online(?:$|:)/, { timeout: 90_000 });
        await expect(flow.page.page.getByTestId("sync-cursor")).toContainText("ak:cursor:", { timeout: 90_000 });
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
    } finally {
      for (const flow of flows) await test.info().attach(`browser-locks-${flow.user.name}`, {
        body: JSON.stringify(await flow.page.page.evaluate(() => navigator.locks.query())),
        contentType: "application/json",
      });
      await Promise.all(flows.map(flow => flow.page.close()));
    }
  });
}
