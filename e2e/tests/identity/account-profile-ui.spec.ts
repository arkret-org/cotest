// Account profile editing through the Inkson settings surface.
// Contract: e2e/scenarios/identity/account-profile-ui.md
// Spec: models/profile.md, interfaces/http-api.md

import { expect, test } from "../../helpers/arkret-test";
import { colandBaseUrl } from "../../helpers/env";
import {
  assertJointStackNotRequired,
  openDpopUserPage,
  selfPathHeadersForDpopSession,
} from "../../helpers/users";

const ONE_PIXEL_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
  "base64",
);

test("@fully-implemented account owner uploads and clears the canonical profile avatar through Settings", async ({
  browser,
  request,
}) => {
  test.setTimeout(240_000);
  const flow = await openDpopUserPage(
    browser,
    request,
    `account-profile-ui-${Date.now()}`,
  );
  if (!flow) {
    assertJointStackNotRequired("account profile settings DPoP login");
    test.skip(true, "coauth DPoP session-grant login is unavailable");
    return;
  }

  const { page, session } = flow;
  const profileUrl = `${colandBaseUrl()}/_arkret/self/account/profile`;
  const viewerUrl = `${colandBaseUrl()}/_arkret/self/account/viewer`;

  try {
    await page.gotoSettings();
    await expect(page.page.getByTestId("settings-avatar-card")).toBeVisible({
      timeout: 60_000,
    });

    const displayName = `Profile ${Date.now()}`;
    const bio = `Bio ${Date.now()}`;
    await page.page.getByTestId("settings-profile-display-name").fill(displayName);
    await page.page.getByTestId("settings-profile-bio").fill(bio);
    const savedTextProfile = page.page.waitForResponse(
      (response) =>
        response.url() === profileUrl &&
        response.request().method() === "POST" &&
        response.status() === 200,
      { timeout: 90_000 },
    );
    await page.page.getByTestId("settings-profile-save").click();
    const savedText = await savedTextProfile;
    expect(savedText.request().postData() ?? "").toMatch(
      /ak\.profile\.(?:create|update)/,
    );
    await expect(page.page.getByTestId("settings-profile-status")).toContainText(
      /saved|已保存/i,
    );
    await expect
      .poll(
        async () => {
          const response = await request.get(viewerUrl, {
            headers: selfPathHeadersForDpopSession(session, "GET", viewerUrl),
          });
          if (!response.ok()) return {};
          const body = (await response.json()) as {
            profile?: {
              display_name?: string;
              profile_fields?: { bio?: string };
            };
          };
          return {
            displayName: body.profile?.display_name,
            bio: body.profile?.profile_fields?.bio,
          };
        },
        { timeout: 60_000, intervals: [250, 500, 1_000, 2_000] },
      )
      .toEqual({ displayName, bio });

    await page.page.getByTestId("settings-avatar-input").setInputFiles({
      name: "avatar.png",
      mimeType: "image/png",
      buffer: ONE_PIXEL_PNG,
    });
    await expect(
      page.page.getByTestId("settings-avatar-upload-cropped"),
    ).toBeVisible({ timeout: 30_000 });

    const publishedProfile = page.page.waitForResponse(
      (response) =>
        response.url() === profileUrl &&
        response.request().method() === "POST" &&
        response.status() === 200,
      { timeout: 90_000 },
    );
    await page.page.getByTestId("settings-avatar-upload-cropped").click();
    const published = await publishedProfile;
    const publishedText = await published.text();
    expect(published.status(), publishedText).toBe(200);
    expect(published.request().postData() ?? "").toContain("ak.profile.update");

    let avatarBlobRef = "";
    await expect
      .poll(
        async () => {
          const response = await request.get(viewerUrl, {
            headers: selfPathHeadersForDpopSession(
              session,
              "GET",
              viewerUrl,
            ),
          });
          if (!response.ok()) return "";
          const body = (await response.json()) as {
            profile?: { avatar_blob_ref?: string | null };
          };
          avatarBlobRef = body.profile?.avatar_blob_ref ?? "";
          return avatarBlobRef;
        },
        { timeout: 60_000, intervals: [250, 500, 1_000, 2_000] },
      )
      .toMatch(/^ak:blob:sha256:[a-f0-9]{64}$/);
    await expect(
      page.page.getByTestId("settings-avatar-preview").locator("img"),
    ).toHaveAttribute("src", /^data:image\//);

    const clearedProfile = page.page.waitForResponse(
      (response) =>
        response.url() === profileUrl &&
        response.request().method() === "POST" &&
        response.status() === 200,
      { timeout: 90_000 },
    );
    await page.page.getByTestId("settings-avatar-clear").click();
    const cleared = await clearedProfile;
    const clearedText = await cleared.text();
    expect(cleared.status(), clearedText).toBe(200);
    expect(cleared.request().postData() ?? "").toContain("ak.profile.update");
    expect(cleared.request().postData() ?? "").not.toContain(avatarBlobRef);

    await expect
      .poll(
        async () => {
          const response = await request.get(viewerUrl, {
            headers: selfPathHeadersForDpopSession(
              session,
              "GET",
              viewerUrl,
            ),
          });
          if (!response.ok()) return avatarBlobRef;
          const body = (await response.json()) as {
            profile?: { avatar_blob_ref?: string | null };
          };
          return body.profile?.avatar_blob_ref ?? "";
        },
        { timeout: 60_000, intervals: [250, 500, 1_000, 2_000] },
      )
      .toBe("");

    await page.page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.page.getByTestId("settings-avatar-card")).toBeVisible({
      timeout: 60_000,
    });
    await expect(page.page.getByTestId("settings-profile-display-name")).toHaveValue(
      displayName,
      { timeout: 60_000 },
    );
    await expect(page.page.getByTestId("settings-profile-bio")).toHaveValue(bio);
    await expect(page.page.getByTestId("settings-avatar-clear")).toHaveCount(0);
  } finally {
    await page.close();
  }
});
