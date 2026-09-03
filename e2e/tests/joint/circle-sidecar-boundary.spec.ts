import { accountActorId } from "../../helpers/soland-api";
import { expect, type APIRequestContext } from "../../helpers/arkret-test";
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
      expect(created.member_ids).toEqual([accountActorId(jointRealm.alice.id)]);
      expect("member_count" in created).toBe(false);
      expect(created.viewer_membership).toBe("join");

      // Fail-closed assertion: the thread-shaped path is not registered and
      // MUST NOT be an alias for the first-class Sidecar API.
      const unregisteredPath = ["", "_arkret", "self", "agent-sidecar-threads:ensure"].join("/");
      const unregisteredUrl = `${solandBaseUrl()}${unregisteredPath}`;
      const unregistered = await request.post(unregisteredUrl, {
        headers: selfPathHeadersForDpopSession(
          jointRealm.aliceSession,
          "POST",
          unregisteredUrl,
        ),
        data: {},
      });
      expect(unregistered.status()).toBe(404);
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
