// Exact-peer complete Consent replacement, explicit confirmation and MIMI replay.
import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { colandBaseUrl, colandServiceId } from "../../helpers/env";
import {
  accountActorId, authHeaders, canonicalJson, canonicalTimestamp, expectJsonOk,
  prepareSignedEventSubmissionApi, principalControlRealmForId,
  principalControlRootAuthorizationRefForId, registeredEventSigningSeedB64url,
  registeredEventVerificationMethod, signedEventEnvelope, sdkMimiConsentProof,
  sdkMimiRequestConsentProof, typedId,
} from "../../helpers/coland-api";
import {
  consentExpectedCurrent, consentPermissions, consentReplacementEvent,
  readConsentCurrentApi, replaceConsentApi, replaceConsentScopeApi,
  type ConsentPermission, type ConsentView,
} from "../../helpers/consent-api";
import {
  assertJointStackNotRequired, ensureRegistered, issueUserSession,
  openDpopUserPage, uniqueUser,
} from "../../helpers/users";
import { selectDxcOption } from "../../helpers/dxc-select";
import { createMimiProvider, postSignedMimiProviderRequest } from "../../helpers/mimi-provider";
import { contactRow, requestContactArkret } from "../../helpers/contact-api";

test.describe.configure({ mode: "serial" });

function consentPeer(peerId: string, stationId = colandServiceId()) {
  return { kind: "actor" as const, actor_id: accountActorId(peerId, undefined, stationId) };
}

async function consentFixture(request: APIRequestContext, suffix: string) {
  const alice = uniqueUser(`consent-set-${suffix}-alice`);
  const bob = uniqueUser(`consent-set-${suffix}-bob`);
  await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
  const token = await issueUserSession(request, alice);
  return { alice, bob, token, peer: consentPeer(bob.id) };
}

test.describe("complete peer Consent", () => {
  test("Contact request and Consent replacement keep their independent current facts", async ({ request }) => {
    const { alice, bob, token, peer } = await consentFixture(request, "contact-independent");
    const bobToken = await issueUserSession(request, bob);
    await requestContactArkret(request, bobToken, alice.id, { requestedScopes: ["invite"] });
    expect((await readConsentCurrentApi(request, token, alice.id, peer)).current).toEqual({ state: "never_written" });
    await expect.poll(async () => (await contactRow(request, token, bob.id))?.state,
      { timeout: 30_000, intervals: [250, 500, 1_000] }).toBe("pending_incoming");
    await replaceConsentScopeApi(request, token, alice.id, peer, "invite", { consent_scope: "invite" });
    expect((await contactRow(request, token, bob.id))?.state).toBe("pending_incoming");
    await replaceConsentScopeApi(request, token, alice.id, peer, "invite", undefined);
    expect((await contactRow(request, token, bob.id))?.state).toBe("pending_incoming");
  });

  test("full read preserves expired, future, unknown constraints and optional presence across replacement and exact retry", async ({ request }) => {
    const { alice, token, peer } = await consentFixture(request, "preserve");
    const absent = await readConsentCurrentApi(request, token, alice.id, peer);
    expect(absent.current).toEqual({ state: "never_written" });
    const original: ConsentPermission[] = [
      { consent_scope: "invite", expires_at: "2020-01-01T00:00:00.000Z", reason: "", constraints: [] },
      { consent_scope: "voice_call", not_before: "2099-01-01T00:00:00.000Z", constraints: [{ unknown: { nested: true } }], evidence_ref: "" },
    ];
    const first = await replaceConsentApi(request, token, alice.id, {
      peer, expected_current: consentExpectedCurrent(absent), permissions: original,
    });
    const full = await readConsentCurrentApi(request, token, alice.id, peer);
    expect(consentPermissions(full)).toEqual(original);
    const added = await replaceConsentScopeApi(request, token, alice.id, peer, "presence", { consent_scope: "presence" });
    expect(consentPermissions(await readConsentCurrentApi(request, token, alice.id, peer))).toEqual([
      ...original, { consent_scope: "presence" },
    ]);
    // Old original bytes may be acknowledged again but cannot overwrite a later set.
    const replay = await expectJsonOk<ConsentView>(await first.submit(), "old exact Consent replacement replay");
    expect(replay.revision).toEqual(first.view.revision);
    const afterReplay = await readConsentCurrentApi(request, token, alice.id, peer);
    expect(consentExpectedCurrent(afterReplay)).toEqual({ state: "present", revision: added.view.revision });
    expect(consentPermissions(afterReplay)).toEqual([...original, { consent_scope: "presence" }]);
  });

  test("empty remains present, stale and never_written CAS cannot reopen it, same principal at another Station is independent", async ({ request }) => {
    const { alice, bob, token, peer } = await consentFixture(request, "cas");
    const never = await readConsentCurrentApi(request, token, alice.id, peer);
    const first = await replaceConsentApi(request, token, alice.id, {
      peer, expected_current: consentExpectedCurrent(never), permissions: [{ consent_scope: "voice_call" }],
    });
    const current = await readConsentCurrentApi(request, token, alice.id, peer);
    const closed = await replaceConsentApi(request, token, alice.id, {
      peer, expected_current: consentExpectedCurrent(current), permissions: [],
    });
    const readClosed = await readConsentCurrentApi(request, token, alice.id, peer);
    expect(readClosed.current.state).toBe("present");
    expect(consentPermissions(readClosed)).toEqual([]);
    expect(consentExpectedCurrent(readClosed)).toEqual({ state: "present", revision: closed.view.revision });
    for (const expected of [consentExpectedCurrent(never), { state: "present" as const, revision: first.view.revision }]) {
      const event = consentReplacementEvent(alice.id, {
        peer, expected_current: expected, permissions: [{ consent_scope: "presence" }],
      });
      const url = `${colandBaseUrl()}/_arkret/self/consent/results/replace`;
      const refused = await request.post(url, {
        headers: { ...authHeaders(token, "POST", url), "content-type": "application/json" },
        data: canonicalJson({ consent_event: { event } }),
      });
      expect(refused.status()).toBe(409);
      expect(consentExpectedCurrent(await readConsentCurrentApi(request, token, alice.id, peer)))
        .toEqual({ state: "present", revision: closed.view.revision });
    }
    const other = consentPeer(bob.id, "ak:did_core:web:other-station.example");
    expect((await readConsentCurrentApi(request, token, alice.id, other)).current).toEqual({ state: "never_written" });
  });

  test("outbound request is opaque and any is rejected", async ({ request }) => {
    const { alice, bob, token, peer } = await consentFixture(request, "request");
    const url = `${colandBaseUrl()}/_arkret/self/consent/request`;
    for (const scope of ["voice_call", "video_call", "presence"]) {
      const response = await request.post(url, {
        headers: { ...authHeaders(token, "POST", url), "content-type": "application/json" },
        data: canonicalJson({ holder_account_id: accountActorId(bob.id).account_id, consent_scope: scope }),
      });
      expect(await expectJsonOk(response, "opaque concrete Consent request")).toEqual({ accepted_for_processing: true });
    }
    const invalid = await request.post(url, {
      headers: { ...authHeaders(token, "POST", url), "content-type": "application/json" },
      data: canonicalJson({ holder_account_id: accountActorId(bob.id).account_id, consent_scope: "any" }),
    });
    expect(invalid.status()).toBe(422);
    expect((await readConsentCurrentApi(request, token, alice.id, peer)).current).toEqual({ state: "never_written" });
  });

  test("settings reads the full original and confirms a real complete diff before replacing", async ({ browser, request }) => {
    test.setTimeout(300_000);
    const bob = uniqueUser("consent-ui-peer");
    await ensureRegistered(request, bob);
    const flow = await openDpopUserPage(browser, request, "consent-ui-holder", { prepareMlsDevice: false });
    if (!flow) {
      assertJointStackNotRequired("Consent full-set UI");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const actor = flow.page;
    const token = await issueUserSession(request, flow.user);
    const peer = consentPeer(bob.id);
    const preserved: ConsentPermission = {
      consent_scope: "invite", expires_at: "2020-01-01T00:00:00.000Z",
      constraints: [{ unknown: { nested: [true, "untouched"] } }], reason: "", evidence_ref: "",
    };
    await replaceConsentScopeApi(request, token, flow.user.id, peer, "invite", preserved);
    try {
      await actor.gotoAppPanel("/settings/consent", "consent-settings-panel");
      await actor.page.getByTestId("consent-peer-input").fill(bob.id);
      await actor.page.getByTestId("consent-peer-station-input").fill(colandServiceId());
      await actor.clickWithPassivePromptRetry(actor.page.getByTestId("consent-read-complete-button"));
      const input = actor.page.getByTestId("consent-permissions-input");
      await expect(input).toBeVisible({ timeout: 30_000 });
      expect(JSON.parse(await input.inputValue())).toEqual([preserved]);
      for (const scope of ["voice_call", "video_call", "presence"]) {
        await actor.page.getByTestId(`consent-toggle-${scope}`).check();
      }
      const replacement: ConsentPermission[] = [
        preserved, { consent_scope: "voice_call" },
        { consent_scope: "video_call" }, { consent_scope: "presence" },
      ];
      expect(JSON.parse(await input.inputValue())).toEqual(replacement);
      await actor.clickWithPassivePromptRetry(actor.page.getByTestId("consent-preview-button"));
      const diff = actor.page.getByTestId("consent-replacement-diff");
      await expect(diff).toBeVisible();
      expect(JSON.parse(await diff.locator("pre").nth(0).innerText())).toEqual([preserved]);
      expect(JSON.parse(await diff.locator("pre").nth(1).innerText())).toEqual(replacement);
      // Preview is not a write; only explicit confirmation changes the current.
      expect(consentPermissions(await readConsentCurrentApi(request, token, flow.user.id, peer))).toEqual([preserved]);
      await actor.clickWithPassivePromptRetry(actor.page.getByTestId("consent-confirm-replace-button"));
      await expect.poll(async () => consentPermissions(await readConsentCurrentApi(request, token, flow.user.id, peer)))
        .toEqual(replacement);
      await expect(actor.page.getByTestId("consent-confirm-replace-button")).toHaveCount(0);

      const extended = await readConsentCurrentApi(request, token, flow.user.id, peer);
      expect(extended.current.state).toBe("present");
      const extendedRevision = consentExpectedCurrent(extended);
      expect(extendedRevision.state).toBe("present");
      if (extendedRevision.state !== "present") {
        throw new Error("confirmed four-scope Consent has no accepted revision");
      }

      // A page reload must retain the complete authenticated set, including
      // inactive permissions and the presence of every optional member.
      await actor.page.reload();
      await actor.gotoAppPanel("/settings/consent", "consent-settings-panel");
      await actor.page.getByTestId("consent-peer-input").fill(bob.id);
      await actor.page.getByTestId("consent-peer-station-input").fill(colandServiceId());
      await actor.clickWithPassivePromptRetry(actor.page.getByTestId("consent-read-complete-button"));
      await expect(input).toBeVisible({ timeout: 30_000 });
      expect(JSON.parse(await input.inputValue())).toEqual(replacement);
      for (const scope of ["invite", "voice_call", "video_call", "presence"]) {
        await expect(actor.page.getByTestId(`consent-toggle-${scope}`)).toBeChecked();
      }
      expect(consentExpectedCurrent(await readConsentCurrentApi(request, token, flow.user.id, peer)))
        .toEqual(extendedRevision);

      for (const scope of ["invite", "voice_call", "video_call", "presence"]) {
        await actor.page.getByTestId(`consent-toggle-${scope}`).uncheck();
      }
      expect(JSON.parse(await input.inputValue())).toEqual([]);
      await actor.clickWithPassivePromptRetry(actor.page.getByTestId("consent-preview-button"));
      await expect(diff).toBeVisible();
      expect(JSON.parse(await diff.locator("pre").nth(0).innerText())).toEqual(replacement);
      expect(JSON.parse(await diff.locator("pre").nth(1).innerText())).toEqual([]);
      const beforeEmptyConfirmation = await readConsentCurrentApi(request, token, flow.user.id, peer);
      expect(consentPermissions(beforeEmptyConfirmation)).toEqual(replacement);
      expect(consentExpectedCurrent(beforeEmptyConfirmation)).toEqual(extendedRevision);
      await actor.clickWithPassivePromptRetry(actor.page.getByTestId("consent-confirm-replace-button"));
      await expect.poll(async () => {
        const current = await readConsentCurrentApi(request, token, flow.user.id, peer);
        return { state: current.current.state, permissions: consentPermissions(current) };
      }).toEqual({ state: "present", permissions: [] });
      await expect(actor.page.getByTestId("consent-confirm-replace-button")).toHaveCount(0);
      const empty = await readConsentCurrentApi(request, token, flow.user.id, peer);
      const emptyRevision = consentExpectedCurrent(empty);
      expect(emptyRevision.state).toBe("present");
      if (emptyRevision.state !== "present") {
        throw new Error("confirmed empty Consent reverted to never_written");
      }
      expect(emptyRevision.revision.stream_position).toBeGreaterThan(extendedRevision.revision.stream_position);
      expect(emptyRevision.revision.commit_id).not.toBe(extendedRevision.revision.commit_id);
      await actor.clickWithPassivePromptRetry(actor.page.getByTestId("consent-read-complete-button"));
      await expect(input).toBeVisible({ timeout: 30_000 });
      expect(JSON.parse(await input.inputValue())).toEqual([]);
      for (const scope of ["invite", "voice_call", "video_call", "presence"]) {
        await expect(actor.page.getByTestId(`consent-toggle-${scope}`)).not.toBeChecked();
      }
      // The opaque request surface contains concrete non-invite scopes only.
      await selectDxcOption(actor.page.getByTestId("consent-request-scope-input"), "video_call");
      await actor.page.getByTestId("consent-request-holder-input").fill(bob.id);
      await actor.page.getByTestId("consent-request-holder-station-input").fill(colandServiceId());
      await actor.clickWithPassivePromptRetry(actor.page.getByTestId("consent-request-submit-button"));
      await expect(actor.page.getByTestId("write-status")).toContainText(/accepted for processing|已受理/i, { timeout: 30_000 });
    } finally {
      await actor.close();
    }
  });
});

test.describe("MIMI complete Consent", () => {
  test("MIMI consent update admits exact Events, rejects conflicts, and hides correlations", async ({
    request,
  }) => {
    const alice = uniqueUser("g2t5-consent-api-alice");
    const bob = uniqueUser("g2t5-consent-api-bob");
    const charlie = uniqueUser("g2t5-consent-api-charlie");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
      ensureRegistered(request, charlie),
    ]);
    // Each principal's canonical session provisions its device signer; only
    // alice's session is used, to prepare her own consent Event.
    const [aliceToken] = await Promise.all([
      issueUserSession(request, alice),
      issueUserSession(request, bob),
      issueUserSession(request, charlie),
    ]);
    const aliceSigningSeed = registeredEventSigningSeedB64url(alice.id);
    const bobSigningSeed = registeredEventSigningSeedB64url(bob.id);
    const charlieSigningSeed = registeredEventSigningSeedB64url(charlie.id);
    if (!aliceSigningSeed || !bobSigningSeed || !charlieSigningSeed) {
      throw new Error("canonical provisioning omitted a MIMI consent device signer");
    }
    const describe = await expectJsonOk<{
      service_id: string;
      trust_domain: string;
    }>(
      await request.get(`${colandBaseUrl()}/_arkret/describe`),
      "MIMI consent destination describe",
    );

    // `mimi_request_consent_request_body` names the requester by complete
    // ActorId and the holder by complete AccountId — consent-model.md §6.1
    // forbids falling back to a bare principal — and requires the requester
    // operation proof over `ak.mimi_request_consent_request_proof.v1`.
    const openUnsigned = {
      requester_actor_id: accountActorId(bob.id),
      holder_account_id: accountActorId(alice.id).account_id,
      purpose: "voice_call",
    };
    const bobVerificationMethod = registeredEventVerificationMethod(bob.id);
    if (!bobVerificationMethod) {
      throw new Error("canonical provisioning omitted bob's device verification method");
    }
    const openProof = sdkMimiRequestConsentProof({
      request: openUnsigned,
      verificationMethod: bobVerificationMethod,
      createdAt: canonicalTimestamp(),
      domain: describe.trust_domain,
      audience: describe.service_id,
      signingSeedB64url: bobSigningSeed,
    });
    // mimi-interop.md section 5: both consent operations are provider-to-
    // provider and MUST carry the RFC 9421 provider-source signature. One
    // provider opens the correlation and answers it, because the correlation
    // is bound to the authenticated source service.
    const provider = createMimiProvider("g2t5-consent");
    const open = await postSignedMimiProviderRequest(
      request,
      provider,
      describe.service_id,
      `${colandBaseUrl()}/_arkret/open/mimi/consent/request`,
      { ...openUnsigned, proofs: [openProof] },
    );
    const openText = await open.text();
    expect(open.status(), openText).toBe(200);
    const openBody = JSON.parse(openText) as Record<string, unknown>;
    // `mimi_request_consent_outcome` is closed over `consent_id` and an
    // optional `challenge`; it carries no status member.
    expect(Object.keys(openBody).filter((key) => key !== "challenge")).toEqual(["consent_id"]);
    expect(openBody.consent_id).toMatch(/^ak:consent:/);

    const updateUrl = `${colandBaseUrl()}/_arkret/open/mimi/consent/update`;
    const peer = { kind: "actor" as const, actor_id: accountActorId(bob.id) };
    const before = await readConsentCurrentApi(request, aliceToken, alice.id, peer);
    const grantEvent = consentReplacementEvent(alice.id, {
      peer, expected_current: consentExpectedCurrent(before),
      permissions: [{ consent_scope: "voice_call" }],
    });
    const consentEvent = await prepareSignedEventSubmissionApi(
      request,
      aliceToken,
      grantEvent,
      { context: "freeze MIMI Consent replacement" },
    );
    const unsignedUpdate = {
      consent_id: openBody.consent_id,
      decision: "accept",
      actor_id: accountActorId(alice.id),
      consent_event: consentEvent,
    };
    const signature = sdkMimiConsentProof({
      request: unsignedUpdate,
      verificationMethod: `${alice.did}#${alice.deviceId}`,
      createdAt: canonicalTimestamp(),
      domain: describe.trust_domain,
      audience: describe.service_id,
      signingSeedB64url: aliceSigningSeed,
    });

    const signedUpdate = { ...unsignedUpdate, signature };
    const update = await postSignedMimiProviderRequest(
      request,
      provider,
      describe.service_id,
      updateUrl,
      signedUpdate,
    );
    const updateText = await update.text();
    expect(update.status(), updateText).toBe(200);
    const updateBody = JSON.parse(updateText);
    // `mimi_update_consent_outcome` reports the decision it admitted.
    expect(updateBody.decision).toBe("accept");
    expect(updateBody.consent_id).toBe(openBody.consent_id);
    expect(updateBody.event_ref).toBe(grantEvent.event_id);

    const replay = await postSignedMimiProviderRequest(
      request,
      provider,
      describe.service_id,
      updateUrl,
      signedUpdate,
    );
    expect(replay.status()).toBe(200);
    const replayBody = await replay.json();
    expect(replayBody).toEqual(updateBody);

    // An exact provider retry returns its original outcome after a later
    // native replacement; it must never restore the old permission set.
    await replaceConsentScopeApi(request, aliceToken, alice.id, peer, "voice_call", undefined);
    const later = await readConsentCurrentApi(request, aliceToken, alice.id, peer);
    const historicalReplay = await postSignedMimiProviderRequest(
      request, provider, describe.service_id, updateUrl, signedUpdate,
    );
    expect(await expectJsonOk(historicalReplay, "MIMI historical exact replay")).toEqual(updateBody);
    expect((await readConsentCurrentApi(request, aliceToken, alice.id, peer)).current).toEqual(later.current);

    const conflictingEvent = signedEventEnvelope({
      actorId: alice.id, realmId: principalControlRealmForId(alice.id),
      eventId: String(grantEvent.event_id),
      authorizationRef: principalControlRootAuthorizationRefForId(alice.id),
      kind: "ak.consent.replace",
      payload: { peer, expected_current: consentExpectedCurrent(before), permissions: [] },
    });
    const conflictingUnsigned = {
      ...unsignedUpdate,
      consent_event: { ...consentEvent, event: conflictingEvent },
    };
    const conflictingBody = {
      ...conflictingUnsigned,
      signature: sdkMimiConsentProof({
        request: conflictingUnsigned,
        verificationMethod: `${alice.did}#${alice.deviceId}`,
        createdAt: canonicalTimestamp(),
        domain: describe.trust_domain,
        audience: describe.service_id,
        signingSeedB64url: aliceSigningSeed,
      }),
    };
    const conflicting = await postSignedMimiProviderRequest(
      request,
      provider,
      describe.service_id,
      updateUrl,
      conflictingBody,
    );
    expect(conflicting.status()).toBe(422);
    const conflictingOutcome = await conflicting.json();
    expect(conflictingOutcome.type).toBe(
      "https://arkret.org/problems/schema_violation",
    );
    expect(conflictingOutcome.reason_code).toBe("event_id_digest_mismatch");

    const invisibleUnsigned = structuredClone(unsignedUpdate);
    invisibleUnsigned.actor_id = accountActorId(charlie.id);
    const invisibleSubmission = invisibleUnsigned.consent_event as Record<
      string,
      unknown
    >;
    const invisibleEvent = invisibleSubmission.event as Record<string, unknown>;
    invisibleEvent.actor_id = accountActorId(charlie.id);
    const invisibleBody = {
      ...invisibleUnsigned,
      signature: sdkMimiConsentProof({
        request: invisibleUnsigned,
        verificationMethod: `${charlie.did}#${charlie.deviceId}`,
        createdAt: canonicalTimestamp(),
        domain: describe.trust_domain,
        audience: describe.service_id,
        signingSeedB64url: charlieSigningSeed,
      }),
    };
    const invisible = await postSignedMimiProviderRequest(
      request,
      provider,
      describe.service_id,
      updateUrl,
      invisibleBody,
    );

    const unknownConsentId = typedId("operation").replace(
      "ak:operation:",
      "ak:consent:",
    );
    const unknownUnsigned = structuredClone(invisibleUnsigned);
    unknownUnsigned.consent_id = unknownConsentId;
    const unknownBody = {
      ...unknownUnsigned,
      signature: sdkMimiConsentProof({
        request: unknownUnsigned,
        verificationMethod: `${charlie.did}#${charlie.deviceId}`,
        createdAt: canonicalTimestamp(),
        domain: describe.trust_domain,
        audience: describe.service_id,
        signingSeedB64url: charlieSigningSeed,
      }),
    };
    const unknown = await postSignedMimiProviderRequest(
      request,
      provider,
      describe.service_id,
      updateUrl,
      unknownBody,
    );
    expect(unknown.status()).toBe(invisible.status());
    const invisibleOutcome = await invisible.json();
    const unknownOutcome = await unknown.json();
    delete invisibleOutcome.request_id;
    delete unknownOutcome.request_id;
    delete invisibleOutcome.instance;
    delete unknownOutcome.instance;
    expect(unknownOutcome).toEqual(invisibleOutcome);
  });

});
