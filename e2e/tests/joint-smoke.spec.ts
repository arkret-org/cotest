import { expect, test, type Page, type Route } from "@playwright/test";
import { coauthBaseUrl, coauthServiceDid, solandBaseUrl, solandServiceDid } from "../helpers/env";
import { stepShot } from "../helpers/screenshots";
import {
  alice,
  bob,
  closeUser,
  ensureRegistered,
  issueDevSession,
  openUser,
  openUserPage,
  uniqueUser,
} from "../helpers/users";

test.describe.configure({ mode: "serial" });

test.beforeEach(async ({ request }) => {
  await ensureRegistered(request, alice);
  await ensureRegistered(request, bob);
});

test("environment health and authenticated live connect render", async ({ browser, request }, testInfo) => {
  const health = await request.get(`${solandBaseUrl()}/health`);
  expect(health.ok()).toBeTruthy();
  const body = await health.json();
  expect(body.ok).toBeTruthy();

  if (coauthBaseUrl()) {
    const coauthHealth = await request.get(`${coauthBaseUrl()}/health`);
    expect(coauthHealth.ok()).toBeTruthy();
  }

  const token = await issueDevSession(request, alice);
  const session = await openUser(browser, alice, token);
  try {
    await session.page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(session.page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
    await stepShot(session.page, testInfo, "01-yougen-loaded");

    await session.page.getByTestId("connect-button").click();
    await expect(session.page.getByTestId("status-label")).toContainText(
      /Connected|Online|Empty|authenticated|principal_server/,
    );
    await stepShot(session.page, testInfo, "02-live-soland-connected");
  } finally {
    await closeUser(session);
  }
});

test("coauth discovery advertises the soland principal-server topology", async ({ request }) => {
  const coauth = coauthBaseUrl();
  test.skip(!coauth, "COTEST_COAUTH_BASE_URL is not configured");

  const coauthWithSlash = `${coauth!.replace(/\/$/, "")}/`;
  const solandWithSlash = `${solandBaseUrl().replace(/\/$/, "")}/`;

  const health = await request.get(`${coauth}/health`);
  expect(health.ok()).toBeTruthy();

  const discoveryResponse = await request.get(`${coauth}/.well-known/openid-configuration`);
  expect(discoveryResponse.ok()).toBeTruthy();
  const discovery = await discoveryResponse.json();
  expect(discovery.issuer).toBe(coauthWithSlash);
  expect(discovery.introspection_endpoint).toBe(`${coauth}/oauth2/introspect`);
  expect(discovery["org.contrix.service_did"]).toBe(coauthServiceDid());

  const discoveryPrincipal = expect.arrayContaining([
    expect.objectContaining({
      name: "soland",
      audience: solandServiceDid(),
      endpoint: solandWithSlash,
      did: solandServiceDid(),
    }),
  ]);
  expect(discovery["org.contrix.principal_servers"]).toEqual(discoveryPrincipal);

  const coauthDescribeResponse = await request.get(`${coauth}/api/v1/server/describe`);
  expect(coauthDescribeResponse.ok()).toBeTruthy();
  const coauthDescribe = await coauthDescribeResponse.json();
  expect(coauthDescribe.service_type).toBe("auth_server");
  expect(coauthDescribe.service_did).toBe(coauthServiceDid());
  expect(coauthDescribe.principal_servers).toEqual(discoveryPrincipal);

  const solandDescribeResponse = await request.get(`${solandBaseUrl()}/api/v1/server/describe`);
  expect(solandDescribeResponse.ok()).toBeTruthy();
  const solandDescribe = await solandDescribeResponse.json();
  expect(solandDescribe.service_type).toBe("principal_server");
  expect(solandDescribe.service_did).toBe(solandServiceDid());
});

test("invalid server URL surfaces an error state with screenshot", async ({ browser }, testInfo) => {
  const session = await openUser(browser, alice);
  try {
    await session.page.goto("/login", { waitUntil: "domcontentloaded" });
    await expect(session.page.getByTestId("login-panel")).toBeVisible({ timeout: 120_000 });

    await session.page.getByTestId("login-server-url").fill("not a url");
    await session.page.getByTestId("start-server-login-button").click();

    await expect(session.page.getByTestId("auth-status")).toContainText(/invalid server URL/i);
    await stepShot(session.page, testInfo, "invalid-url-error");
  } finally {
    await closeUser(session);
  }
});

test("coauth sign-in metadata failure is shown on the login screen", async ({ browser }, testInfo) => {
  const session = await openUser(browser, alice);
  try {
    await installCoauthMetadataFailureMock(session.page);
    await session.page.goto("/login", { waitUntil: "domcontentloaded" });
    await session.page.getByTestId("login-server-url").fill("http://127.0.0.1:1");
    await session.page.getByTestId("login-account-hint").fill("unknown@example.test");
    await session.page.getByTestId("start-server-login-button").click();

    await expect(session.page.getByTestId("auth-status")).toContainText(/Server sign-in metadata failed/i);
    await stepShot(session.page, testInfo, "coauth-metadata-error");
  } finally {
    await closeUser(session);
  }
});

test("invalid session grant is rejected when live coauth introspection is configured", async ({
  browser,
  request,
}, testInfo) => {
  test.skip(!coauthBaseUrl(), "COTEST_COAUTH_BASE_URL is not configured");

  const response = await request.post(`${solandBaseUrl()}/api/v1/auth/session-grant/exchange`, {
    data: {
      grant_jwt: "not-a-real-session-grant",
      principal_did: alice.did,
      device_id: alice.deviceId,
    },
  });
  expect(response.status()).toBe(403);
  const body = await response.json();
  expect(JSON.stringify(body)).toMatch(/session grant|coauth|rejected|not active/i);

  const session = await openUser(browser, alice);
  try {
    await session.page.goto("/login", { waitUntil: "domcontentloaded" });
    await expect(session.page.getByTestId("login-panel")).toBeVisible();
    await stepShot(session.page, testInfo, "session-grant-rejected-login-state");
  } finally {
    await closeUser(session);
  }
});

test("registers a generated user through the product account flow", async ({ browser, request }, testInfo) => {
  const user = uniqueUser("register");
  const operatorToken = await issueDevSession(request, alice);
  const actor = await openUserPage(browser, alice, operatorToken);
  try {
    await actor.gotoProduct();
    await actor.page.getByTestId("account-register-did-input").fill(user.did);
    await actor.page.getByTestId("account-register-handle-input").fill(user.handle);
    await actor.page.getByTestId("account-register-display-name-input").fill(user.displayName);
    await actor.page.getByTestId("account-register-device-id-input").fill(user.deviceId);
    await stepShot(actor.page, testInfo, "01-registration-form-filled");

    await actor.page.getByTestId("register-account-button").click();
    await expect(actor.page.getByTestId("account-flow")).toContainText(`registered ${user.handle}`);
    await stepShot(actor.page, testInfo, "02-registration-submitted");

    const token = await issueDevSession(request, user);
    const me = await request.get(`${solandBaseUrl()}/api/v1/account/me`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(me.status()).toBe(200);
    const body = await me.json();
    expect(body.did).toBe(user.did);
    expect(body.handle).toBe(user.handle);
    expect(body.display_name).toBe(user.displayName);
  } finally {
    await actor.close();
  }
});

test("alice and bob hold isolated dev-login browser sessions", async ({ browser, request }, testInfo) => {
  for (const user of [alice, bob]) {
    const token = await issueDevSession(request, user);
    const actor = await openUserPage(browser, user, token);
    try {
      await actor.gotoHome();
      await actor.connect();
      await actor.expectPrincipal();
      await stepShot(actor.page, testInfo, `${user.name}-dev-login`);
    } finally {
      await actor.close();
    }
  }
});

test("alice and bob complete the contact request and duplicate-conflict flow", async ({
  browser,
  request,
}, testInfo) => {
  const contactAlice = uniqueUser("contact-alice");
  const contactBob = uniqueUser("contact-bob");
  await ensureRegistered(request, contactAlice);
  await ensureRegistered(request, contactBob);

  const aliceToken = await issueDevSession(request, contactAlice);
  const bobToken = await issueDevSession(request, contactBob);
  const aliceActor = await openUserPage(browser, contactAlice, aliceToken);
  const bobActor = await openUserPage(browser, contactBob, bobToken);

  try {
    await aliceActor.gotoDirectory();
    await aliceActor.page.getByTestId("tab-actors").click();
    await aliceActor.page.getByTestId("directory-search-input").fill(contactBob.handle);
    await aliceActor.page.getByTestId("directory-search-button").click();
    await expect(aliceActor.page.getByTestId("directory-panel")).toContainText(/No actors found/);
    await stepShot(aliceActor.page, testInfo, "01-alice-searches-bob-before-contact");

    await aliceActor.gotoProduct();
    await aliceActor.page.getByTestId("contact-target-did-input").fill(contactBob.did);
    await stepShot(aliceActor.page, testInfo, "02-alice-contact-request-ready");
    await aliceActor.page.getByTestId("request-contact-button").click();
    await expect(aliceActor.page.getByTestId("contact-flow")).toContainText(/pending/);
    await stepShot(aliceActor.page, testInfo, "03-alice-contact-request-pending");

    await aliceActor.page.getByTestId("request-contact-button").click();
    await expect(aliceActor.page.getByTestId("contact-flow")).toContainText(/pending/);
    await stepShot(aliceActor.page, testInfo, "04-alice-duplicate-request-idempotent");

    await bobActor.gotoProduct();
    await bobActor.page.getByTestId("contact-requester-did-input").fill(contactAlice.did);
    await bobActor.page.getByTestId("accept-contact-button").click();
    await expect(bobActor.page.getByTestId("contact-flow")).toContainText(/accepted/);
    await stepShot(bobActor.page, testInfo, "05-bob-accepts-contact");

    await bobActor.page.getByTestId("list-contacts-button").click();
    await expect(bobActor.page.getByTestId("contact-flow")).toContainText(contactAlice.did);
    await expect(bobActor.page.getByTestId("contact-flow")).toContainText(/contacts 1/);
    await stepShot(bobActor.page, testInfo, "06-bob-contact-list");

    await bobActor.page.getByTestId("contact-target-did-input").fill(contactAlice.did);
    await bobActor.page.getByTestId("request-contact-button").click();
    await expect(bobActor.page.getByTestId("contact-flow")).toContainText(
      /request failed|already exists|409|duplicate/i,
    );
    await stepShot(bobActor.page, testInfo, "07-bob-reverse-duplicate-conflict");

    await aliceActor.gotoDirectory();
    await aliceActor.page.getByTestId("tab-actors").click();
    await aliceActor.page.getByTestId("directory-search-input").fill(contactBob.handle);
    await aliceActor.page.getByTestId("directory-search-button").click();
    await expect(aliceActor.page.getByTestId("actor-result")).toContainText(contactBob.did);
    await stepShot(aliceActor.page, testInfo, "08-alice-finds-bob-after-contact");
  } finally {
    await bobActor.close();
    await aliceActor.close();
  }
});

test("alice manages a private space lifecycle with invite, metadata, policy, membership, and delete", async ({
  browser,
  request,
}, testInfo) => {
  const owner = uniqueUser("space-owner");
  const invitee = uniqueUser("space-invitee");
  await ensureRegistered(request, owner);
  await ensureRegistered(request, invitee);

  const ownerToken = await issueDevSession(request, owner);
  const inviteeToken = await issueDevSession(request, invitee);
  const ownerActor = await openUserPage(browser, owner, ownerToken);
  const inviteeActor = await openUserPage(browser, invitee, inviteeToken);
  const stamp = Date.now();
  const title = `Private Lifecycle Space ${stamp}`;
  const renamed = `Renamed Lifecycle Space ${stamp}`;

  try {
    await ownerActor.gotoProduct();
    await ownerActor.page.getByTestId("space-title-input").fill(title);
    await ownerActor.page.getByTestId("space-summary-input").fill("private lifecycle coverage");
    await ownerActor.page.getByTestId("space-discoverability-input").fill("invite_only");
    await ownerActor.page.getByTestId("member-did-input").fill(invitee.did);
    await stepShot(ownerActor.page, testInfo, "01-private-space-form");

    await ownerActor.page.getByTestId("create-space-button").click();
    await expect(ownerActor.page.getByTestId("space-lifecycle-flow")).toContainText(/created cx:space:/);
    const spaceId = await extractCreatedSpaceId(ownerActor.page);
    await stepShot(ownerActor.page, testInfo, "02-private-space-created");

    const anonymousSearch = await request.post(`${solandBaseUrl()}/api/v1/directory/search-spaces`, {
      data: { query: title },
    });
    expect(anonymousSearch.status()).toBe(200);
    expect((await anonymousSearch.json()).results).toHaveLength(0);

    await inviteeActor.gotoProduct();
    await inviteeActor.page.getByTestId("list-invites-button").click();
    await expect(inviteeActor.page.getByTestId("space-lifecycle-flow")).toContainText(spaceId);
    await stepShot(inviteeActor.page, testInfo, "03-invitee-sees-pending-invite");

    await ownerActor.gotoProduct();
    await ownerActor.page.getByTestId("selected-space-id-input").fill(spaceId);
    await ownerActor.page.getByTestId("space-title-input").fill(renamed);
    await ownerActor.page.getByTestId("space-summary-input").fill("renamed private lifecycle coverage");
    await ownerActor.page.getByTestId("space-discoverability-input").fill("restricted");
    await ownerActor.page.getByTestId("update-space-button").click();
    await expect(ownerActor.page.getByTestId("space-lifecycle-flow")).toContainText(`updated ${spaceId}`);
    await stepShot(ownerActor.page, testInfo, "04-space-metadata-updated");

    const ownerSearch = await request.post(`${solandBaseUrl()}/api/v1/directory/search-spaces`, {
      headers: { authorization: `Bearer ${ownerToken}` },
      data: { query: renamed },
    });
    expect(ownerSearch.status()).toBe(200);
    expect((await ownerSearch.json()).results).toEqual(
      expect.arrayContaining([expect.objectContaining({ space_id: spaceId, name: renamed })]),
    );

    await ownerActor.page.getByTestId("space-policy-join-rule-input").fill("restricted");
    await ownerActor.page.getByTestId("space-policy-history-visibility-input").fill("invited");
    await ownerActor.page.getByTestId("set-space-policy-button").click();
    await expect(ownerActor.page.getByTestId("space-lifecycle-flow")).toContainText(/policy restricted invited/);
    await stepShot(ownerActor.page, testInfo, "05-space-policy-updated");

    await ownerActor.page.getByTestId("member-did-input").fill(invitee.did);
    await ownerActor.page.getByTestId("add-member-button").click();
    await expect(ownerActor.page.getByTestId("space-lifecycle-flow")).toContainText(/members 2/);
    await stepShot(ownerActor.page, testInfo, "06-space-member-added");

    await ownerActor.page.getByTestId("remove-member-button").click();
    await expect(ownerActor.page.getByTestId("space-lifecycle-flow")).toContainText(/removed; members 1/);
    await stepShot(ownerActor.page, testInfo, "07-space-member-removed");

    await ownerActor.page.getByTestId("delete-space-button").click();
    await expect(ownerActor.page.getByTestId("space-lifecycle-flow")).toContainText(/deleted true/);
    await stepShot(ownerActor.page, testInfo, "08-space-deleted");

    const deletedSearch = await request.post(`${solandBaseUrl()}/api/v1/directory/search-spaces`, {
      headers: { authorization: `Bearer ${ownerToken}` },
      data: { query: renamed },
    });
    expect(deletedSearch.status()).toBe(200);
    expect((await deletedSearch.json()).results).toEqual(
      expect.not.arrayContaining([expect.objectContaining({ space_id: spaceId })]),
    );
  } finally {
    await inviteeActor.close();
    await ownerActor.close();
  }
});

test("alice and bob exchange, sync, edit, and redact timeline messages", async ({
  browser,
  request,
}, testInfo) => {
  const msgAlice = uniqueUser("msg-alice");
  const msgBob = uniqueUser("msg-bob");
  await ensureRegistered(request, msgAlice);
  await ensureRegistered(request, msgBob);

  const aliceToken = await issueDevSession(request, msgAlice);
  const bobToken = await issueDevSession(request, msgBob);
  const aliceActor = await openUserPage(browser, msgAlice, aliceToken);
  const bobActor = await openUserPage(browser, msgBob, bobToken);
  const stamp = Date.now();
  const title = `Message Flow Space ${stamp}`;
  const aliceMessage = `alice says hello ${stamp}`;
  const bobReply = `bob replies ${stamp}`;
  const bobEdited = `bob reply edited ${stamp}`;

  try {
    await aliceActor.gotoProduct();
    const aliceSpaceFlow = aliceActor.page.getByTestId("space-lifecycle-flow").first();
    await aliceSpaceFlow.getByTestId("space-title-input").fill(title);
    await aliceSpaceFlow.getByTestId("space-summary-input").fill("bidirectional message coverage");
    await aliceSpaceFlow.getByTestId("space-discoverability-input").fill("public");
    await aliceSpaceFlow.getByTestId("member-did-input").fill(msgBob.did);
    await aliceSpaceFlow.getByTestId("create-space-button").click();
    await expect(aliceSpaceFlow).toContainText(/created cx:space:/);
    const spaceId = await extractCreatedSpaceId(aliceActor.page);
    await aliceSpaceFlow.getByTestId("add-member-button").click();
    await expect(aliceSpaceFlow).toContainText(/members 2/);
    await stepShot(aliceActor.page, testInfo, "01-message-space-ready");

    await gotoTimelineSpace(aliceActor.page, spaceId);
    await aliceActor.page.getByTestId("composer-input").fill(aliceMessage);
    await aliceActor.page.getByTestId("send-button").click();
    await expect(aliceActor.page.getByTestId("timeline")).toContainText(aliceMessage);
    await expect(aliceActor.page.getByTestId("write-status")).toContainText(/persisted/);
    await stepShot(aliceActor.page, testInfo, "02-alice-message-sent");

    const bobSyncAfterAlice = await request.post(`${solandBaseUrl()}/api/v1/sync`, {
      headers: { authorization: `Bearer ${bobToken}` },
      data: {},
    });
    expect(bobSyncAfterAlice.status()).toBe(200);
    expect(JSON.stringify(await bobSyncAfterAlice.json())).toContain(aliceMessage);

    await bobActor.gotoHome();
    await bobActor.connect();
    await expect(bobActor.page.getByTestId("sync-cursor")).toContainText(/cursor cx:cursor:/);
    await gotoTimelineSpace(bobActor.page, spaceId);
    await expect(bobActor.page.getByTestId("timeline")).toContainText(aliceMessage);
    await stepShot(bobActor.page, testInfo, "03-bob-syncs-alice-message");

    await bobActor.page.getByTestId("composer-input").fill(bobReply);
    await bobActor.page.getByTestId("send-button").click();
    await expect(bobActor.page.getByTestId("timeline")).toContainText(bobReply);
    await expect(bobActor.page.getByTestId("write-status")).toContainText(/persisted/);
    await stepShot(bobActor.page, testInfo, "04-bob-reply-sent");

    const aliceSync = await request.post(`${solandBaseUrl()}/api/v1/sync`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: {},
    });
    expect(aliceSync.status()).toBe(200);
    expect(JSON.stringify(await aliceSync.json())).toContain(bobReply);

    const replyEvent = bobActor.page.getByTestId("timeline-event").filter({ hasText: bobReply });
    await replyEvent.getByTestId("edit-button").click();
    await bobActor.page.getByTestId("edit-composer").locator("textarea").fill(bobEdited);
    await bobActor.page.getByTestId("save-edit-button").click();
    await expect(bobActor.page.getByTestId("timeline-event").filter({ hasText: bobEdited })).toBeVisible();
    await expect(bobActor.page.getByTestId("write-status")).toContainText(/revised/);
    await stepShot(bobActor.page, testInfo, "05-bob-reply-edited");

    const editedEvent = bobActor.page.getByTestId("timeline-event").filter({ hasText: bobEdited });
    await editedEvent.getByTestId("redact-button").click();
    await bobActor.page.getByTestId("confirm-redact-button").click();
    await expect(bobActor.page.getByTestId("redacted-tombstone")).toBeVisible();
    await expect(bobActor.page.getByTestId("write-status")).toContainText(/tombstoned/);
    await stepShot(bobActor.page, testInfo, "06-bob-reply-redacted");
  } finally {
    await bobActor.close();
    await aliceActor.close();
  }
});

test("guest, non-member, and non-owner permission paths are blocked", async ({
  browser,
  request,
}, testInfo) => {
  const owner = uniqueUser("perm-owner");
  const member = uniqueUser("perm-member");
  const outsider = uniqueUser("perm-outsider");
  const guestUser = uniqueUser("perm-guest");
  await ensureRegistered(request, owner);
  await ensureRegistered(request, member);
  await ensureRegistered(request, outsider);

  const ownerToken = await issueDevSession(request, owner);
  const outsiderToken = await issueDevSession(request, outsider);
  const ownerActor = await openUserPage(browser, owner, ownerToken);
  const outsiderActor = await openUserPage(browser, outsider, outsiderToken);
  const guestActor = await openUserPage(browser, guestUser);
  const stamp = Date.now();
  const title = `Permission Flow Space ${stamp}`;

  try {
    await guestActor.page.goto("/product", { waitUntil: "domcontentloaded" });
    await expect(guestActor.page.getByTestId("login-panel")).toBeVisible({ timeout: 120_000 });
    await expect(guestActor.page.getByTestId("product-panel")).toHaveCount(0);
    await stepShot(guestActor.page, testInfo, "01-guest-product-routed-to-login");

    await ownerActor.gotoProduct();
    const ownerSpaceFlow = ownerActor.page.getByTestId("space-lifecycle-flow").first();
    await ownerSpaceFlow.getByTestId("space-title-input").fill(title);
    await ownerSpaceFlow.getByTestId("space-summary-input").fill("permission coverage");
    await ownerSpaceFlow.getByTestId("space-discoverability-input").fill("invite_only");
    await ownerSpaceFlow.getByTestId("member-did-input").fill(member.did);
    await ownerSpaceFlow.getByTestId("create-space-button").click();
    await expect(ownerSpaceFlow).toContainText(/created cx:space:/);
    const spaceId = await extractCreatedSpaceId(ownerActor.page);
    await stepShot(ownerActor.page, testInfo, "02-private-permission-space-created");

    const unauthUpdate = await request.patch(`${solandBaseUrl()}/api/v1/spaces/${spaceId}`, {
      data: { title: `${title} unauth` },
    });
    expect(unauthUpdate.status()).toBe(401);

    const outsiderUpdate = await request.patch(`${solandBaseUrl()}/api/v1/spaces/${spaceId}`, {
      headers: { authorization: `Bearer ${outsiderToken}` },
      data: { title: `${title} denied` },
    });
    expect(outsiderUpdate.status()).toBe(403);

    const outsiderAddMember = await request.post(`${solandBaseUrl()}/api/v1/spaces/${spaceId}/members`, {
      headers: { authorization: `Bearer ${outsiderToken}` },
      data: { member: outsider.did },
    });
    expect(outsiderAddMember.status()).toBe(403);

    await outsiderActor.gotoProduct();
    const outsiderSpaceFlow = outsiderActor.page.getByTestId("space-lifecycle-flow").first();
    await outsiderSpaceFlow.getByTestId("selected-space-id-input").fill(spaceId);
    await outsiderSpaceFlow.getByTestId("space-title-input").fill(`${title} UI denied`);
    await outsiderSpaceFlow.getByTestId("update-space-button").click();
    await expect(outsiderSpaceFlow).toContainText(/update failed:.*(403|owner|policy_denied)/);
    await stepShot(outsiderActor.page, testInfo, "03-non-owner-update-denied");

    await gotoTimelineSpace(outsiderActor.page, spaceId);
    await outsiderActor.page.getByTestId("composer-input").fill(`outsider blocked ${stamp}`);
    await outsiderActor.page.getByTestId("send-button").click();
    await expect(outsiderActor.page.getByTestId("write-status")).toContainText(
      /send failed:.*(403|policy_denied|not a member)/,
    );
    await stepShot(outsiderActor.page, testInfo, "04-non-member-message-denied");
  } finally {
    await guestActor.close();
    await outsiderActor.close();
    await ownerActor.close();
  }
});

test("session refresh, logout, and revoked token paths are enforced", async ({
  browser,
  request,
}, testInfo) => {
  const user = uniqueUser("session-user");
  await ensureRegistered(request, user);

  const token = await issueDevSession(request, user);
  const actor = await openUserPage(browser, user, token);

  try {
    await actor.gotoSettings();
    await expect(actor.page.getByTestId("session-panel")).toContainText(/Token loaded/);
    await stepShot(actor.page, testInfo, "01-session-loaded");

    await actor.page.getByTestId("session-refresh-button").click();
    await expect(actor.page.getByTestId("session-state")).toContainText(/session refresh ok: did:web:/);
    await expect(actor.page.getByTestId("session-state")).toContainText(user.did);
    await stepShot(actor.page, testInfo, "02-session-refresh-ok");

    const liveMe = await request.get(`${solandBaseUrl()}/api/v1/account/me`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(liveMe.status()).toBe(200);

    await actor.page.getByTestId("session-logout-button").click();
    await expect(actor.page.getByTestId("login-panel")).toBeVisible({ timeout: 120_000 });
    await expect(actor.page.getByTestId("session-panel")).toHaveCount(0);
    await expect
      .poll(() =>
        actor.page.evaluate(() => {
          const raw = window.localStorage.getItem("yougen.config.v1");
          return raw ? JSON.parse(raw).session_token : null;
        }),
      )
      .toBe("");
    await stepShot(actor.page, testInfo, "03-session-logout-routes-login");

    const revokedMe = await request.get(`${solandBaseUrl()}/api/v1/account/me`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(revokedMe.status()).toBe(401);
    expect(JSON.stringify(await revokedMe.json())).toMatch(/revoked|unauthenticated|auth_expired/i);
    await stepShot(actor.page, testInfo, "04-revoked-token-blocked");
  } finally {
    await actor.close();
  }
});

test("alice creates a live space and persists a message", async ({ browser, request }, testInfo) => {
  const token = await issueDevSession(request, alice);
  const session = await openUser(browser, alice, token);
  const stamp = Date.now();
  const title = `Joint E2E Space ${stamp}`;
  const message = `joint e2e message ${stamp}`;

  try {
    await session.page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(session.page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
    await session.page.getByTestId("connect-button").click();
    await expect(session.page.getByTestId("principal-context")).toContainText(alice.did);
    await expect(session.page.getByTestId("status-label")).toContainText(
      /Connected|Online|Empty|authenticated|principal_server/,
    );
    await stepShot(session.page, testInfo, "01-alice-logged-in");

    await session.page.getByTestId("product-nav-button").click();
    await expect(session.page.getByTestId("product-panel")).toBeVisible();
    const spaceFlow = session.page.getByTestId("space-lifecycle-flow").first();
    await spaceFlow.getByTestId("space-title-input").fill(title);
    await spaceFlow.getByTestId("space-discoverability-input").fill("public");
    await spaceFlow.getByTestId("member-did-input").fill(bob.did);
    await spaceFlow.getByTestId("create-space-button").click();
    await expect(spaceFlow).toContainText(/created cx:space:/);
    await stepShot(session.page, testInfo, "02-space-created");

    await session.page.getByTestId("persist-message-input").fill(message);
    await session.page.getByTestId("persist-message-button").click();
    await expect(session.page.getByTestId("message-persistence-flow")).toContainText(/persisted/);
    await stepShot(session.page, testInfo, "03-message-persisted");

    await session.page.getByRole("link", { name: "Timeline" }).click();
    await expect(session.page.getByTestId("timeline")).toContainText(/persisted event|joint e2e message/);
    await stepShot(session.page, testInfo, "04-timeline-visible");
  } finally {
    await closeUser(session);
  }
});

async function installCoauthMetadataFailureMock(page: Page) {
  await page.route("http://127.0.0.1:1/**", async (route) => {
    if (await fulfillCorsPreflight(route)) {
      return;
    }
    await fulfillJson(route, 503, {
      ok: false,
      error: {
        code: "coauth_metadata_unavailable",
        message: "mock coauth metadata failure",
      },
    });
  });
}

async function fulfillCorsPreflight(route: Route): Promise<boolean> {
  if (route.request().method() !== "OPTIONS") {
    return false;
  }
  await route.fulfill({
    status: 204,
    headers: corsHeaders(),
  });
  return true;
}

async function fulfillJson(route: Route, status: number, body: unknown) {
  await route.fulfill({
    status,
    headers: {
      ...corsHeaders(),
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

function corsHeaders(): Record<string, string> {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "authorization,content-type,idempotency-key,x-contrix-request-id",
  };
}

async function extractCreatedSpaceId(page: Page): Promise<string> {
  const text = await page.getByTestId("space-lifecycle-flow").first().innerText();
  const match = text.match(/created (cx:space:[^\s]+)/);
  expect(match, `created space id in: ${text}`).not.toBeNull();
  return match![1];
}

async function gotoTimelineSpace(page: Page, spaceId: string) {
  const href = `/timeline/${spaceId}`;
  const spaceLink = page.locator(`a[data-testid="space-button"][href="${href}"]`).first();
  if ((await spaceLink.count()) > 0) {
    await spaceLink.click();
  } else {
    await page.goto(href, { waitUntil: "domcontentloaded" });
  }
  await expect(page.getByTestId("timeline")).toBeVisible({ timeout: 120_000 });
}
