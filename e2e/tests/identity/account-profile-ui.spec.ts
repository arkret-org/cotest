// Account profile editing through the Inkson settings surface.
// Contract: e2e/scenarios/identity/account-profile-ui.md
// Spec: models/profile.md, interfaces/http-api.md

import { expect, test } from "../../helpers/arkret-test";
import { colandBaseUrl } from "../../helpers/env";
import { openRegisteredUserPage } from "../../helpers/users";

const ONE_PIXEL_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
  "base64",
);

test("@fully-implemented account owner uploads, cold-loads and clears the canonical profile avatar through Settings", async ({ browser, request }) => {
  test.setTimeout(480_000);
  const { page } = await openRegisteredUserPage(browser, request, `account-profile-ui-${Date.now()}`);
  const profileUrl = `${colandBaseUrl()}/_arkret/self/account/profile`;
  const viewerUrl = `${colandBaseUrl()}/_arkret/self/account/viewer`;
  const profileWrite = () => page.page.waitForResponse(response =>
    response.url() === profileUrl && response.request().method() === "POST", { timeout: 90_000 });
  const coldViewer = async () => {
    const viewer = page.page.waitForResponse(response =>
      response.url() === viewerUrl && response.request().method() === "GET" && response.status() === 200,
      { timeout: 90_000 });
    await page.page.reload({ waitUntil: "domcontentloaded" });
    // Observe the product's authenticated read, including its real refresh chain.
    return (await (await viewer).json()).profile;
  };
  try {
    await page.gotoSettings();
    await expect(page.page.getByTestId("settings-avatar-card")).toBeVisible({ timeout: 60_000 });
    const displayName = `Profile ${Date.now()}`;
    const biography = `Bio ${Date.now()}`;
    await page.page.getByTestId("settings-profile-display-name").fill(displayName);
    await page.page.getByTestId("settings-profile-biography").fill(biography);
    const savedTextProfile = profileWrite();
    await page.page.getByTestId("settings-profile-save").click();
    const savedText = await savedTextProfile;
    expect(savedText.status()).toBe(200);
    expect(savedText.request().postData() ?? "").toMatch(/ak\.profile\.(?:create|update)/);
    await expect(page.page.getByTestId("settings-profile-status")).toContainText(/saved|已保存/i);

    await page.page.getByTestId("settings-avatar-input").setInputFiles({ name: "avatar.png", mimeType: "image/png", buffer: ONE_PIXEL_PNG });
    await expect(page.page.getByTestId("settings-avatar-upload-cropped")).toBeVisible({ timeout: 30_000 });
    const publishedProfile = profileWrite();
    await page.page.getByTestId("settings-avatar-upload-cropped").click();
    const published = await publishedProfile;
    expect(published.status()).toBe(200);
    expect(published.request().postData() ?? "").toContain("ak.profile.update");
    await expect(page.page.getByTestId("settings-avatar-preview").locator("img")).toHaveAttribute("src", /^data:image\//);

    const restoredProfile = await coldViewer();
    expect(restoredProfile.display_name).toBe(displayName);
    expect(restoredProfile.profile_fields?.biography).toBe(biography);
    const avatarBlobRef = restoredProfile.avatar_blob_ref;
    expect(avatarBlobRef).toMatch(/^ak:blob:sha256:[a-f0-9]{64}$/);
    const restoredAvatar = page.page.getByTestId("settings-avatar-preview").locator("img");
    await expect(restoredAvatar).toBeVisible({ timeout: 90_000 });
    await expect.poll(() => restoredAvatar.evaluate((image: HTMLImageElement) =>
      image.complete && image.naturalWidth > 0), { timeout: 60_000 }).toBe(true);
    await expect(page.page.getByTestId("settings-avatar-preview").getByTestId("content-block-blob-error")).toHaveCount(0);

    const clearedProfile = profileWrite();
    await page.page.getByTestId("settings-avatar-clear").click();
    const cleared = await clearedProfile;
    expect(cleared.status()).toBe(200);
    expect(cleared.request().postData() ?? "").toContain("ak.profile.update");
    expect(cleared.request().postData() ?? "").not.toContain(avatarBlobRef);
    const emptyProfile = await coldViewer();
    expect(emptyProfile.avatar_blob_ref ?? "").toBe("");
    await expect(page.page.getByTestId("settings-avatar-card")).toBeVisible({ timeout: 60_000 });
    await expect(page.page.getByTestId("settings-profile-display-name")).toHaveValue(displayName);
    await expect(page.page.getByTestId("settings-profile-biography")).toHaveValue(biography);
    await expect(page.page.getByTestId("settings-avatar-clear")).toHaveCount(0);
  } finally { await page.close(); }
});
