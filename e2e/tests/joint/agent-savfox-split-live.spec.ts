import { expect } from "@playwright/test";
import { test as jointTest } from "../../helpers/joint-fixture";

jointTest.describe.configure({ mode: "serial" });

jointTest.describe("Agent Savfox split live @fully-implemented", () => {
  jointTest(
    "creates and approves in Inkson, survives refresh, and opens a Savfox session",
    async ({ browser, jointRealm }) => {
      jointTest.setTimeout(600_000);

      // The joint harness does not provision the out-of-tree savfox gateway,
      // so this live pairing scenario only runs when both endpoints are
      // supplied externally. Follow the repo convention (README test tiers:
      // "a missing prerequisite must be an explicit test.skip with a
      // machine-readable reason") and skip instead of hard-throwing, which
      // otherwise reds the smoke/full gate on every run.
      const savfoxBaseUrlRaw = process.env.COTEST_SAVFOX_BASE_URL?.trim();
      const savfoxTokenRaw = process.env.COTEST_SAVFOX_TOKEN?.trim();
      jointTest.skip(
        !savfoxBaseUrlRaw || !savfoxTokenRaw,
        "PRECONDITION_SAVFOX_UNAVAILABLE: COTEST_SAVFOX_BASE_URL / COTEST_SAVFOX_TOKEN unset (harness does not provision the savfox gateway)",
      );
      const savfoxBaseUrl = savfoxBaseUrlRaw!.replace(/\/$/, "");
      const savfoxToken = savfoxTokenRaw!;
      const inkson = jointRealm.alicePage.page;
      const agentSlug = `savfox-live-${Date.now().toString(36)}`;

      await jointRealm.alicePage.gotoSettings();
      await inkson.getByTestId("settings-nav-item-agents").click();
      await expect(inkson).toHaveURL(/\/settings\/agents(?:\?|$)/);
      await inkson.getByTestId("agent-admin-create-open-button").click();
      await inkson
        .getByTestId("agent-admin-provision-agent-slug")
        .fill(agentSlug);
      await expect(
        inkson.getByTestId("agent-admin-provision-button"),
      ).toBeEnabled();
      await inkson.getByTestId("agent-admin-provision-button").click();
      const pairingCard = inkson.getByTestId("agent-admin-pairing-card");
      await expect(pairingCard).toBeVisible({ timeout: 180_000 });
      const pairingLink = await inkson
        .getByTestId("agent-admin-pairing-url")
        .inputValue();
      expect(pairingLink).toContain(
        "/_arkret/open/agent-pairing/resolve#token=",
      );

      const savfoxContext = await browser.newContext();
      const savfox = await savfoxContext.newPage();
      try {
        await savfox.goto(`${savfoxBaseUrl}/channels/edit/arkret`);
        const tokenInput = savfox.getByPlaceholder("Gateway token", {
          exact: true,
        });
        if (await tokenInput.isVisible()) {
          await tokenInput.fill(savfoxToken);
          await savfox.getByRole("button", { name: "Connect" }).click();
        }
        await expect(
          savfox.getByRole("heading", { name: "Configure Arkret" }),
        ).toBeVisible({ timeout: 30_000 });

        await savfox
          .getByPlaceholder(
            "https://arkret.example.org/_arkret/open/agent-pairing/resolve#token=...",
            { exact: true },
          )
          .fill(pairingLink);
        const startPairing = savfox.getByRole("button", {
          name: "Start pairing",
          exact: true,
        });
        await expect(startPairing).toBeEnabled();
        await startPairing.click();

        const approvalModal = inkson.getByTestId(
          "agent-runtime-approval-modal",
        );
        await expect(approvalModal).toBeVisible({ timeout: 120_000 });
        const inksonCode = (
          await inkson.getByTestId("agent-runtime-approval-code").innerText()
        ).trim();
        expect(inksonCode).toMatch(/^\d{8}$/);
        const groupedPairingCode = `${inksonCode.slice(0, 4)} ${inksonCode.slice(4)}`;
        await expect(
          savfox.getByText(groupedPairingCode, { exact: true }),
        ).toBeVisible();
        await expect(
          savfox.getByText(
            `Waiting for Inkson approval... Compare pairing code ${inksonCode} with the Inkson prompt.`,
          ),
        ).toBeVisible({ timeout: 30_000 });

        await inkson.getByTestId("agent-runtime-approval-approve").click();
        await expect(approvalModal).toHaveCount(0, { timeout: 180_000 });
        await expect(
          savfox.getByText("Agent paired and channel saved.", { exact: true }),
        ).toBeVisible({
          timeout: 180_000,
        });

        await savfox
          .getByRole("button", { name: "Save changes", exact: true })
          .click();
        await expect(
          savfox.getByRole("heading", { name: "Configure Arkret" }),
        ).toHaveCount(0, { timeout: 120_000 });
        const arkretCard = savfox
          .locator(".channels-card")
          .filter({ hasText: "Arkret" });
        await expect(arkretCard).toHaveCount(1);
        await expect(arkretCard).toContainText(/Pairing\s*Paired/, {
          timeout: 120_000,
        });
        await expect
          .poll(
            async () => {
              await savfox.reload();
              await expect(arkretCard).toHaveCount(1);
              return (await arkretCard.textContent()) ?? "";
            },
            {
              timeout: 120_000,
              intervals: [1_000, 2_000, 5_000],
              message: "Savfox should surface the live Arkret session",
            },
          )
          .toContain("Listening");

        await inkson.reload();
        await expect(inkson.getByTestId("personal-agent-admin")).toBeVisible({
          timeout: 120_000,
        });
        await expect(
          inkson.getByTestId("agent-runtime-approval-modal"),
        ).toHaveCount(0);
        await expect(
          inkson.getByTestId("agent-admin-pairing-card"),
        ).toHaveCount(0);

        await inkson.getByTestId("realm-sidebar-tab-direct").click();
        const ownAgentRow = inkson
          .getByTestId("contact-sidebar-self-group")
          .getByTestId("contact-sidebar-agent-row")
          .filter({ hasText: agentSlug });
        await expect(ownAgentRow).toBeVisible({ timeout: 120_000 });
        await ownAgentRow.click();
        await expect(inkson.getByTestId("chat-panel")).toBeVisible({
          timeout: 120_000,
        });
        await expect(inkson.getByTestId("chat-input")).toBeVisible({
          timeout: 30_000,
        });

        const prompt = "请只回复 pong";
        await inkson.getByTestId("chat-input").fill(prompt);
        await jointRealm.alicePage.clickWithPassivePromptRetry(
          inkson.getByTestId("send-chat-button"),
        );
        await expect(
          inkson.getByTestId("chat-message").filter({ hasText: prompt }),
        ).toBeVisible({ timeout: 30_000 });

        const pongBody = inkson
          .getByTestId("content-block-text")
          .filter({ hasText: /^pong(?:\r?\n|$)/ });
        const pongMessage = inkson
          .getByTestId("chat-message")
          .filter({ has: pongBody });
        await expect(pongMessage).toBeVisible({ timeout: 180_000 });
        expect((await pongBody.innerText()).split(/\r?\n/, 1)[0]).toBe("pong");
        await expect(pongMessage).toHaveAttribute(
          "data-crypto-state",
          "plaintext",
        );
        await expect(
          pongMessage.getByTestId("member-badge-agent"),
        ).toBeVisible();
        await expect(
          pongMessage.getByTestId("crypto-status-needs-verification"),
        ).toHaveCount(0);
      } finally {
        await savfoxContext.close();
      }
    },
  );
});
