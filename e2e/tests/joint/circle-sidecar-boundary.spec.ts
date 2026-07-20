import { expect, type APIRequestContext } from "@playwright/test";
import type { CircleOutcome } from "../../helpers/circle-api";
import { solandBaseUrl } from "../../helpers/env";
import { test as jointTest } from "../../helpers/joint-fixture";
import {
  selfPathHeadersForDpopSession,
  type DpopUserSession,
} from "../../helpers/users";

jointTest.describe.configure({ mode: "serial" });

jointTest.describe("Circle and Sidecar object boundary @fully-implemented", () => {
  jointTest(
    "creates ordinary Circle membership and rejects the retired Sidecar endpoint",
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
      expect(created.join_rule).toBe("public");
      expect(created.display.short_name).toBeTruthy();
      expect(created.display.color_token).toBeTruthy();
      expect(created.display.symbol).toBeTruthy();
      expect(created.members).toEqual([jointRealm.alice.did]);
      expect(created.member_count).toBe(1);
      expect(created.viewer_membership).toBe("join");

      // Negative migration assertion: the retired thread-shaped path is not
      // an alias for the first-class Sidecar API.
      const legacyPath = "/_arkret/self/agent-sidecar-" + "threads:ensure";
      const legacyUrl = `${solandBaseUrl()}${legacyPath}`;
      const legacy = await request.post(legacyUrl, {
        headers: selfPathHeadersForDpopSession(
          jointRealm.aliceSession,
          "POST",
          legacyUrl,
        ),
        data: {},
      });
      expect(legacy.status()).toBe(404);
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
