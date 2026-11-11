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
      const panel = alice.page.page.locator(".realm-invite-links");
      await panel.getByLabel("Maximum different accounts", { exact: true }).fill("2");
      await panel.getByRole("button", { name: "Prepare invitation", exact: true }).click();
      await expect(panel.locator(".realm-invite-link-message")).toContainText("prepared locally", { timeout: 60_000 });
      await panel.getByRole("button", { name: "Publish / retry same invitation", exact: true }).click();
      const shared = panel.locator("textarea.realm-invite-link-share");
      const shareReadyDeadline = performance.now() + 90_000;
      await expect(shared).toBeVisible({ timeout: 90_000 });
      const shareReadyRemaining = shareReadyDeadline - performance.now();
      if (shareReadyRemaining <= 0) throw new Error("Invitation readiness exceeded its original 90 second budget");
      await expect.poll(async () => {
        const remaining = shareReadyDeadline - performance.now();
        if (remaining <= 0) return false;
        return (await shared.inputValue({ timeout: remaining })).includes("lt=invite");
      }, {
        timeout: shareReadyRemaining,
        message: "Authority acceptance must render the private invitation within the original readiness budget",
      }).toBe(true);
      const link = await shared.inputValue();
      expect(link.includes("lt=invite"), "authority accepted the private share link").toBe(true);
      for (const member of [bob, carol]) {
        await member.page.page.goto("/realms/manage");
        const join = member.page.page.locator(".realm-invite-links");
        await join.getByLabel("Paste invitation link after signing in", { exact: true }).fill(link);
        await join.locator(".realm-invite-link-confirm").click();
        await expect(join.locator(".realm-invite-link-message")).toContainText("Joined. Membership is accepted", { timeout: 120_000 });
      }
      // realm-invite-links.md: joining grants no message-writing capability.
      for (const member of [bob, carol]) {
        await alice.page.gotoRealmAdminSection(realm, "security");
        await alice.page.page.locator(".advanced-access-toggle").click();
        await alice.page.page.locator(".cap-grant-tag-input input").fill("ak.message.create");
        await alice.page.page.locator(".cap-grant-subject-input input").fill(JSON.stringify({
          principal_id: member.user.id, station_id: colandServiceId(),
        }));
        await expect(alice.page.page.locator(".cap-grant-submit-button")).toBeEnabled({ timeout: 60_000 });
        await alice.page.page.locator(".cap-grant-submit-button").click();
        await expect(alice.page.page.locator(".realm-settings-content > .write-status")).toContainText("Permission granted. Grant ID:", { timeout: 120_000 });
      }
      for (const flow of flows) {
        await flow.page.page.goto(`/chat/${realm}`);
        await flow.page.page.reload({ waitUntil: "domcontentloaded" });
        await expect(flow.page.page.getByRole("textbox", { name: "Message", exact: true })).toBeVisible({ timeout: 90_000 });
        await expect(flow.page.page.locator(".connection-status .status-label")).toHaveText(/^Online(?:$|:)/, { timeout: 90_000 });
        await expect(flow.page.page.locator(".connection-status .sync-cursor")).toContainText("ak:cursor:", { timeout: 90_000 });
      }
      for (const author of flows) {
        const body = `Accepted shared message ${author.user.name} ${stamp}`;
        const page = author.page.page;
        await expect(page.locator(".send-chat-button")).toBeEnabled({ timeout: 120_000 });
        await page.getByRole("textbox", { name: "Message", exact: true }).fill(body);
        await page.locator(".send-chat-button").click();
        const own = page.locator(".chat-message").filter({ hasText: body });
        await expect(own).toHaveCount(1, { timeout: 60_000 });
        await expect(own.locator(".message-send-status")).toHaveCount(0, { timeout: 90_000 });
        for (const reader of flows) await expect(reader.page.page.getByText(body, { exact: true })).toBeVisible({ timeout: 90_000 });
      }
      await bob.page.gotoRealmAdminSection(realm, "repair");
      await bob.page.page.locator(".leave-realm-button").click();
      await bob.page.page.locator(".leave-realm-confirm-button").click();
      await expect(bob.page.page.locator(".realm-settings-content > .write-status")).toContainText(/^left /, { timeout: 90_000 });
      for (const member of [alice, carol]) {
        await member.page.page.goto(`/realms/${realm}/members`);
        await member.page.page.reload({ waitUntil: "domcontentloaded" });
        await expect(member.page.page.locator(".realm-members-card .member-head-actions > .member-count-badge")).toHaveText("2", { timeout: 90_000 });
      }
      if (encrypted) {
        // A changed roster must converge to a covered epoch that still sends.
        // Membership count alone does not establish encrypted collaboration.
        for (const member of [alice, carol]) await member.page.gotoTimelineRealm(realm);
        const afterLeave: string[] = [];
        for (const author of [alice, carol]) {
          const body = `After Bob left ${author.user.name} ${stamp}`;
          afterLeave.push(body);
          await author.page.sendTimelineMessage(realm, body);
          for (const reader of [alice, carol]) await reader.page.expectTimelineEventVisible(body, 120_000);
        }
        await bob.page.page.goto(`/chat/${realm}`, { waitUntil: "domcontentloaded" });
        await expect(bob.page.page.locator(".shell.app")).toBeVisible({ timeout: 90_000 });
        await expect(bob.page.page.locator(".connection-status .status-label")).toHaveText(/^Online(?:$|:)/, { timeout: 90_000 });
        await expect(bob.page.page.locator(".connection-status .sync-cursor")).toContainText("ak:cursor:", { timeout: 90_000 });
        await expect(bob.page.page.locator(".send-chat-button:enabled")).toHaveCount(0);
        for (const body of afterLeave) await expect(bob.page.page.getByText(body, { exact: true })).toHaveCount(0);
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
