import { expect, type APIRequestContext } from "@playwright/test";
import type { CircleOutcome } from "../../helpers/circle-api";
import { solandBaseUrl } from "../../helpers/env";
import { test as jointTest } from "../../helpers/joint-fixture";
import {
  selfPathHeadersForDpopSession,
  type DpopUserSession,
} from "../../helpers/users";

jointTest.describe.configure({ mode: "serial" });

jointTest.describe("Circle and Sidecar projection boundary @fully-implemented", () => {
  jointTest(
    "creates the initial membership and hides a Sidecar-profile Circle from the ordinary UI",
    async ({ jointRealm, request }) => {
      jointTest.setTimeout(360_000);
      const page = jointRealm.alicePage.page;
      const title = `Joint Circle ${Date.now()}`;

      await page.goto(`/realms/${encodeURIComponent(jointRealm.realmId)}/circles`, {
        waitUntil: "domcontentloaded",
      });
      await expect(page.getByTestId("circles-panel")).toBeVisible();
      await page.getByTestId("circle-create-open").click();
      await page.getByTestId("circle-create-title").fill(title);
      await page.getByTestId("circle-create-submit").click();

      await expect(page).toHaveURL(/\/realms\/[^/]+\/circles\/[^/]+$/);
      await expect(page.getByTestId("circle-detail")).toContainText(title);

      const circleId = decodeURIComponent(page.url().split("/").at(-1) ?? "");
      const created = await getCircle(request, jointRealm.aliceSession, circleId);
      expect(created.profile_ref).toBeUndefined();
      expect(created.join_rule).toBe("open");
      expect(created.display.short_name).toBeTruthy();
      expect(created.display.color_token).toBeTruthy();
      expect(created.display.symbol).toBeTruthy();
      expect(created.members).toEqual([jointRealm.alice.did]);
      expect(created.member_count).toBe(1);
      expect(created.viewer_membership).toBe("join");

      const sidecarTitle = `Injected Sidecar ${Date.now()}`;
      await page.route(
        ({ pathname }) => pathname === "/_arkret/self/circles",
        async (route) => {
          if (route.request().method() !== "GET") {
            await route.continue();
            return;
          }
          const upstream = await route.fetch();
          const body = (await upstream.json()) as { circles?: CircleOutcome[] };
          const sidecar: CircleOutcome = {
            ...created,
            circle_id: "ak:circle:01964137-0000-7000-8000-0000000000c1",
            profile_ref: "ak.profile.agent_sidecar_thread.v1",
            title: sidecarTitle,
          };
          await route.fulfill({
            response: upstream,
            json: { ...body, circles: [...(body.circles ?? []), sidecar] },
          });
        },
      );

      await page.goto(`/realms/${encodeURIComponent(jointRealm.realmId)}/circles`, {
        waitUntil: "domcontentloaded",
      });
      await expect(page.getByTestId("circle-list-item").filter({ hasText: title })).toBeVisible();
      await expect(page.getByText(sidecarTitle, { exact: true })).toHaveCount(0);
    },
  );
});

async function getCircle(
  request: APIRequestContext,
  session: DpopUserSession,
  circleId: string,
): Promise<CircleOutcome> {
  const url = `${solandBaseUrl()}/_arkret/self/circles/${encodeURIComponent(circleId)}`;
  const response = await request.get(url, {
    headers: selfPathHeadersForDpopSession(session, "GET", url),
  });
  const text = await response.text();
  expect(response.status(), text).toBe(200);
  return JSON.parse(text) as CircleOutcome;
}
