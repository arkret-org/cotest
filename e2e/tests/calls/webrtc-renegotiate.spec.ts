// WebRTC renegotiation and device switch coverage.
// Contract: e2e/scenarios/calls/webrtc-renegotiate.md

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  DEMO_ALICE_DEVICE_ID,
  DEMO_ALICE_DID,
  DEMO_REALM_ID,
  authHeaders,
  closeCallSession,
  createCallSession,
  demoAliceToken,
  getCallSignals,
  postCallSignal,
} from "../../helpers/webrtc";

test.describe("cx.call.signal renegotiation", () => {
  test("ICE config, device_change, and renegotiate stay in seq order", async ({
    request,
  }) => {
    const token = await demoAliceToken(request);
    const sessionId = await createCallSession(request, token);
    try {
      const ice = await request.post(
        `${solandBaseUrl()}/cokret/v1/ice-config`,
        {
          headers: authHeaders(token),
          data: {
            realm_id: DEMO_REALM_ID,
            call_id: sessionId,
            actor_id: DEMO_ALICE_DID,
            device_id: DEMO_ALICE_DEVICE_ID,
          },
        },
      );
      expect(ice.status(), "signed ICE config").toBe(200);
      const iceBody = await ice.json();
      expect(iceBody.signature?.payload_digest).toMatch(/^sha256:/);
      expect(Array.isArray(iceBody.ice_servers)).toBe(true);

      await postCallSignal(request, token, sessionId, "device_change", 1, {
        old_device_id: DEMO_ALICE_DEVICE_ID,
        new_device_id: DEMO_ALICE_DEVICE_ID,
        reason: "camera-switch",
      });
      await postCallSignal(request, token, sessionId, "renegotiate", 2, {
        ice_restart: true,
        because: "device_change",
      });

      const tail = await getCallSignals(request, token, sessionId, 1);
      expect(tail).toHaveLength(1);
      expect(tail[0].seq).toBe(2);
      expect(tail[0].type).toBe("renegotiate");
      expect(tail[0].device_proof).toMatchObject({ actor: DEMO_ALICE_DID });
    } finally {
      await closeCallSession(request, token, sessionId);
    }
  });
});
