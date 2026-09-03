// Principal-private file transfer through Inkson's /files surface.
// Contract: e2e/scenarios/encryption/file-transfer.md
// Spec: models/file-transfer.md, crypto-media/media-and-blob.md

import {
  expect,
  test,
  type Response,
} from "../../helpers/arkret-test";
import { solandBaseUrl } from "../../helpers/env";
import {
  assertJointStackNotRequired,
  openDpopUserPage,
  selfPathHeadersForDpopSession,
} from "../../helpers/users";

test("@fully-implemented actor-private file upload stores ciphertext while Inkson restores the plaintext filename", async ({
  browser,
  request,
}) => {
  test.setTimeout(300_000);
  const stamp = Date.now();
  const filename = `private-note-${stamp}.txt`;
  const plaintext = Buffer.from(`actor-private plaintext ${stamp}`, "utf8");
  const flow = await openDpopUserPage(
    browser,
    request,
    `file-transfer-${stamp}`,
  );
  if (!flow) {
    assertJointStackNotRequired("file transfer DPoP login");
    test.skip(true, "coauth DPoP session-grant login is unavailable");
    return;
  }

  const { page, session } = flow;
  try {
    await page.gotoFileTransfer();
    const relevantResponses: Response[] = [];
    page.page.on("response", (response) => {
      if (
        response.url().includes("/_arkret/self/blob/upload") ||
        response.url().includes("/_arkret/self/account_data/")
      ) {
        relevantResponses.push(response);
      }
    });
    const status = page.page.getByTestId("file-transfer-status");
    const fileChooser = page.page.waitForEvent("filechooser");
    await page.page.getByTestId("file-transfer-upload-button").click();
    await (await fileChooser).setFiles({
      name: filename,
      mimeType: "text/plain",
      buffer: plaintext,
    });
    await expect(status).not.toHaveText("Ready", { timeout: 10_000 });
    await expect(status).toHaveText("Upload complete", { timeout: 90_000 });

    await expect
      .poll(
        () =>
          relevantResponses.find(
            (response) =>
              response.url().includes("/_arkret/self/blob/upload") &&
              response.request().method() === "POST",
          ),
        { timeout: 30_000 },
      )
      .toBeDefined();
    const uploaded = relevantResponses.find(
      (response) =>
        response.url().includes("/_arkret/self/blob/upload") &&
        response.request().method() === "POST",
    )!;
    const uploadedText = await uploaded.text();
    expect(uploaded.status(), uploadedText).toBeLessThan(400);
    const uploadBody = JSON.parse(uploadedText) as { blob_ref?: string };
    expect(uploadBody.blob_ref).toMatch(/^ak:blob:sha256:[a-f0-9]{64}$/);
    const uploadWire = uploaded.request().postData() ?? "";
    expect(uploadWire).not.toContain(filename);
    expect(uploadWire).not.toContain(plaintext.toString("utf8"));

    await expect
      .poll(
        () =>
          relevantResponses.find(
            (response) =>
              response.url().includes("/_arkret/self/account_data/") &&
              response.request().method() !== "GET",
          ),
        { timeout: 30_000 },
      )
      .toBeDefined();
    const recorded = relevantResponses.find(
      (response) =>
        response.url().includes("/_arkret/self/account_data/") &&
        response.request().method() !== "GET",
    )!;
    const recordedText = await recorded.text();
    expect(recorded.status(), recordedText).toBeLessThan(400);
    const accountDataWire = recorded.request().postData() ?? "";
    expect(accountDataWire).toContain(
      "ak.schema.account_data_encrypted_value.v1",
    );
    expect(accountDataWire).not.toContain(filename);
    expect(accountDataWire).not.toContain(plaintext.toString("utf8"));

    const row = page.page
      .getByTestId("file-transfer-row")
      .filter({ hasText: filename })
      .first();
    await expect(row).toBeVisible({ timeout: 60_000 });
    await expect(row).toContainText("text/plain");
    await expect(row).toContainText("available");

    const blobRef = uploadBody.blob_ref!;
    const downloadUrl = `${solandBaseUrl()}/_arkret/self/blob/get?blob_ref=${encodeURIComponent(blobRef)}&purpose=file_transfer`;
    const downloaded = await request.get(downloadUrl, {
      headers: selfPathHeadersForDpopSession(
        session,
        "GET",
        downloadUrl,
      ),
    });
    const ciphertext = await downloaded.body();
    expect(downloaded.status()).toBe(200);
    expect(
      (downloaded.headers()["content-type"] ?? "").toLowerCase(),
    ).toContain("application/octet-stream");
    expect(Buffer.compare(ciphertext, plaintext)).not.toBe(0);
    expect(ciphertext.toString("utf8")).not.toContain(
      plaintext.toString("utf8"),
    );

    await page.page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.page.getByTestId("file-transfer-panel")).toBeVisible({
      timeout: 60_000,
    });
    await expect(
      page.page
        .getByTestId("file-transfer-row")
        .filter({ hasText: filename })
        .first(),
    ).toBeVisible({ timeout: 60_000 });
  } finally {
    await page.close();
  }
});
