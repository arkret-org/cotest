// Calls — canonical wire surfaces (1:1 signaling + ICE config + TURN pseudonym).
// Contract: e2e/scenarios/calls/webrtc.md
// Spec refs:
//   - crypto-media/webrtc-signaling.md §3 (ck.call.* capabilities)
//   - webrtc-signaling.md §4-§4.2 (ICE config, pairwise pseudonym, mid-call refresh)
//   - webrtc-signaling.md §5-§6 (signaling envelope, 1:1 payloads)
//
// WIRE NOTE (migration): the retired `/_soland/self/webrtc/sessions` +
// `/_soland/self/calls/*` stack (session create/close, server-derived
// `call_state`, `recording/start`, `ice-config/refresh`) is gone. The UI / live
// recording flows that drove it were yougen-UI coverage, not protocol wire, and
// are out of scope for the cotest wire surface — this file now exercises only
// the canonical surfaces: `POST /_cokret/self/ephemeral` (ck.call.signal),
// `POST /_cokret/self/rtc/ice-config`. Recording lifecycle is a durable
// `ck.call.state` projection pinned by the Rust call-state conformance vectors;
// mid-call TURN refresh is simply a re-call of the ICE config endpoint (§4.2).

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";
import { addRealmMemberApi, createRealmApi } from "../../helpers/soland-api";
import {
  CAP_CALL_SIGNAL_SEND,
  buildCallSignalEnvelope,
  fetchIceConfig,
  grantCallCapability,
  newCallId,
  postCallSignal,
  relayedCallSignals,
} from "../../helpers/webrtc";

test.describe.configure({ mode: "serial" });

test.describe("calls — canonical wire", () => {
  test("ICE config endpoint rejects unauthenticated callers and signs an authenticated response", async ({
    request,
  }) => {
    const alice = uniqueUser(`s18-probe-${Date.now()}`);
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, token, {
      title: `S18 probe ${Date.now()}`,
      public: true,
    });
    const callId = newCallId();

    const iceProbe = await request.post(
      `${solandBaseUrl()}/_cokret/self/rtc/ice-config`,
      {
        data: {
          realm_id: realmId,
          call_id: callId,
          actor_id: alice.did,
          device_id: alice.deviceId,
          mode: "p2p",
        },
      },
    );
    // Unauthenticated MUST be rejected.
    expect([401, 403]).toContain(iceProbe.status());

    const iceAuth = await fetchIceConfig(request, token, {
      realm_id: realmId,
      call_id: callId,
      actor_id: alice.did,
      device_id: alice.deviceId,
      mode: "p2p",
    });
    expect(iceAuth.status(), await iceAuth.text()).toBe(200);
    const body = await iceAuth.json();
    expect(Array.isArray(body.ice_servers)).toBe(true);
    expect(body.signature.signature_input).toBe("ck.media.ice_config.v1");
  });

  test("1:1 invite -> answer -> candidate -> hangup relays verbatim with proof + monotonic per-sender seq", async ({
    request,
  }) => {
    const { alice, aliceToken, bob, bobToken, realmId } = await setupCallRealm(
      request,
      "s18-1to1",
    );
    await grantCallCapability(
      request,
      aliceToken,
      alice.did,
      realmId,
      bob.did,
      CAP_CALL_SIGNAL_SEND,
    );
    const callId = newCallId();

    await postCallSignal(
      request,
      aliceToken,
      buildCallSignalEnvelope({
        actorDid: alice.did,
        deviceId: alice.deviceId,
        realmId,
        callId,
        signalType: "invite",
        seq: 1,
        data: { mode: "p2p", offer: { type: "offer", sdp: "v=0\r\no=alice" } },
      }),
    );
    await postCallSignal(
      request,
      bobToken,
      buildCallSignalEnvelope({
        actorDid: bob.did,
        deviceId: bob.deviceId,
        realmId,
        callId,
        signalType: "answer",
        seq: 1,
        data: { answer: { type: "answer", sdp: "v=0\r\no=bob" } },
      }),
    );
    await postCallSignal(
      request,
      aliceToken,
      buildCallSignalEnvelope({
        actorDid: alice.did,
        deviceId: alice.deviceId,
        realmId,
        callId,
        signalType: "hangup",
        seq: 2,
        data: { reason: "user_hangup" },
      }),
    );

    const bobView = (
      await relayedCallSignals(request, bobToken, realmId)
    ).filter(
      (env) => (env.payload as Record<string, unknown>)?.call_id === callId,
    );
    const aliceView = (
      await relayedCallSignals(request, aliceToken, realmId)
    ).filter(
      (env) => (env.payload as Record<string, unknown>)?.call_id === callId,
    );
    const bobTypes = bobView.map(
      (e) => (e.payload as Record<string, unknown>).signal_type,
    );
    const aliceTypes = aliceView.map(
      (e) => (e.payload as Record<string, unknown>).signal_type,
    );
    expect(bobTypes).toEqual(expect.arrayContaining(["invite", "hangup"]));
    expect(bobTypes).not.toContain("answer");
    expect(aliceTypes).toEqual(expect.arrayContaining(["answer"]));
    // Every relayed frame carries a verifiable detached-JWS proof (§5.1).
    for (const env of [...bobView, ...aliceView]) {
      const proof = env.proof as Record<string, unknown>;
      expect(proof.kind).toBe("detached_jws");
      expect(proof.alg).toBe("EdDSA");
      expect(proof.verification_method).toBe(`${env.actor_id}#${env.device_id}`);
    }
    // Alice's lane is seq-monotonic (invite=1, hangup=2).
    const aliceSeqs = bobView
      .filter((e) => e.actor_id === alice.did)
      .map((e) => (e.payload as Record<string, unknown>).seq as number);
    expect(aliceSeqs).toEqual([1, 2]);
    const bobSeqs = aliceView
      .filter((e) => e.actor_id === bob.did)
      .map((e) => (e.payload as Record<string, unknown>).seq as number);
    expect(bobSeqs).toEqual([1]);
  });

  test("§4.2 mid-call TURN refresh is a re-call of the ICE config endpoint; pseudonym is bucket-stable", async ({
    request,
  }) => {
    const { alice, aliceToken, realmId } = await setupCallRealm(
      request,
      "s18-turn-refresh",
    );
    const callId = newCallId();

    const issuedResp = await fetchIceConfig(request, aliceToken, {
      realm_id: realmId,
      call_id: callId,
      actor_id: alice.did,
      device_id: alice.deviceId,
      mode: "p2p",
    });
    expect(issuedResp.status(), await issuedResp.text()).toBe(200);
    const issued = await issuedResp.json();

    // Refresh = re-call the same endpoint (no dedicated refresh route exists).
    const refreshedResp = await fetchIceConfig(request, aliceToken, {
      realm_id: realmId,
      call_id: callId,
      actor_id: alice.did,
      device_id: alice.deviceId,
      mode: "p2p",
    });
    expect(refreshedResp.status()).toBe(200);
    const refreshed = await refreshedResp.json();

    expect(issued.bucket_seconds).toBe(300);
    expect(refreshed.bucket_seconds).toBe(300);
    expect(iceBucketUnix(issued)).toBe(floorToBucketUnix(issued.issued_at, 300));
    expect(iceBucketUnix(refreshed)).toBe(
      floorToBucketUnix(refreshed.issued_at, 300),
    );
    // §4.1/§4.2 — within the same pseudonym bucket an active leg keeps its
    // pseudonym. The REST username expiry can still move, which changes the
    // username and HMAC credential.
    const issuedTurn = turnOf(issued);
    const refreshedTurn = turnOf(refreshed);
    expect(issuedTurn, "issued ICE config carries a TURN server").toBeTruthy();
    expect(
      refreshedTurn,
      "refreshed ICE config carries a TURN server",
    ).toBeTruthy();
    const issuedUsername = parseTurnUsername(issuedTurn.username as string);
    const refreshedUsername = parseTurnUsername(
      refreshedTurn.username as string,
    );
    if (iceBucketUnix(refreshed) === iceBucketUnix(issued)) {
      expect(refreshedUsername.pseudonym).toBe(issuedUsername.pseudonym);
    }
    expect(refreshedUsername.expiryUnix).toBeGreaterThanOrEqual(
      issuedUsername.expiryUnix,
    );
    expect(issuedTurn.credential).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(refreshedTurn.credential).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(refreshed.refresh_lead_seconds).toBeGreaterThan(0);
    expect(refreshed.refresh_lead_seconds).toBeLessThan(refreshed.ttl_seconds);
  });

  test("§4.1 TURN pseudonym: username is REST-style and never leaks the principal DID", async ({
    request,
  }) => {
    const { alice, aliceToken, bob, bobToken, realmId } = await setupCallRealm(
      request,
      "s18-turn-pseudonym",
    );
    const callId = newCallId();

    const aliceResp = await fetchIceConfig(request, aliceToken, {
      realm_id: realmId,
      call_id: callId,
      actor_id: alice.did,
      device_id: alice.deviceId,
      mode: "p2p",
    });
    const bobResp = await fetchIceConfig(request, bobToken, {
      realm_id: realmId,
      call_id: callId,
      actor_id: bob.did,
      device_id: bob.deviceId,
      mode: "p2p",
    });
    expect(aliceResp.status(), await aliceResp.text()).toBe(200);
    expect(bobResp.status(), await bobResp.text()).toBe(200);
    const aliceIce = await aliceResp.json();
    const bobIce = await bobResp.json();
    const aliceTurn = turnOf(aliceIce);
    const bobTurn = turnOf(bobIce);
    expect(aliceTurn).toBeTruthy();
    expect(bobTurn).toBeTruthy();
    const aliceUsername = aliceTurn.username as string;
    const bobUsername = bobTurn.username as string;

    // REST-style username = `<expiry-unix>:ck_pseudonym_call_<16hex>` (§4.1).
    const aliceParsed = parseTurnUsername(aliceUsername);
    const bobParsed = parseTurnUsername(bobUsername);
    expect(aliceParsed.expiryUnix).toBe(
      Math.floor(new Date(aliceTurn.expires_at as string).getTime() / 1000),
    );
    // credential = base64(HMAC-SHA256(turn_shared_secret, username)).
    expect(aliceTurn.credential).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(bobTurn.credential).toMatch(/^[A-Za-z0-9+/]+=*$/);
    // No principal identity leaks into the pseudonym.
    expect(aliceUsername).not.toContain(alice.did);
    expect(aliceUsername).not.toContain("did:web");
    expect(aliceUsername).not.toContain(alice.name);
    expect(bobUsername).not.toContain(bob.did);
    expect(bobUsername).not.toContain("did:web");
    expect(bobUsername).not.toContain(bob.name);
    // Distinct principals get distinct pseudonyms.
    expect(bobParsed.pseudonym).not.toBe(aliceParsed.pseudonym);
  });
});

async function setupCallRealm(request: APIRequestContext, label: string) {
  const stamp = Date.now();
  const alice = uniqueUser(`${label}-alice-${stamp}`);
  const bob = uniqueUser(`${label}-bob-${stamp}`);
  await Promise.all([
    ensureRegistered(request, alice),
    ensureRegistered(request, bob),
  ]);
  const aliceToken = await issueDevSession(request, alice);
  const bobToken = await issueDevSession(request, bob);
  const realmId = await createRealmApi(request, aliceToken, {
    title: `S18 ${label} ${stamp}`,
    public: true,
  });
  await addRealmMemberApi(request, aliceToken, realmId, bob.did);
  return { alice, bob, aliceToken, bobToken, realmId };
}

// `issued_at_bucket` is an RFC3339 timestamp; collapse it to the unix-second
// bucket boundary for comparison.
function iceBucketUnix(ice: { issued_at_bucket: string }): number {
  return Math.floor(new Date(ice.issued_at_bucket).getTime() / 1000);
}

function floorToBucketUnix(issuedAt: string, bucketSeconds: number): number {
  const issuedUnix = Math.floor(new Date(issuedAt).getTime() / 1000);
  return Math.floor(issuedUnix / bucketSeconds) * bucketSeconds;
}

function turnOf(ice: any): any {
  return ice.ice_servers.find((s: any) => typeof s.username === "string");
}

function parseTurnUsername(username: string): {
  expiryUnix: number;
  pseudonym: string;
} {
  const match = username.match(/^(\d+):(ck_pseudonym_call_[0-9a-f]{16})$/);
  expect(match, `TURN username must be REST-style: ${username}`).not.toBeNull();
  return { expiryUnix: Number(match![1]), pseudonym: match![2] };
}
