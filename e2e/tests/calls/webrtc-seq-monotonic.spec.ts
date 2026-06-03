// WebRTC seq monotonicity guards.
// Contract: e2e/scenarios/calls/webrtc-seq-monotonic.md

import { expect, test } from "@playwright/test";
import {
  authHeaders,
  closeCallSession,
  createCallSession,
  demoAliceToken,
  deviceProof,
  expectCallSignalError,
  getCallSignals,
  postCallSignal,
} from "../../helpers/webrtc";
import { solandBaseUrl } from "../../helpers/env";

test.describe("ck.call.signal seq monotonicity", () => {
  test("rollback from seq N to N-1 is rejected and preserves the frontier", async ({
    request,
  }) => {
    const token = await demoAliceToken(request);
    const sessionId = await createCallSession(request, token);
    try {
      await postCallSignal(request, token, sessionId, "offer", 1, {
        sdp: "v=0",
      });
      await postCallSignal(request, token, sessionId, "answer", 2, {
        sdp: "v=0",
      });

      const rollback = await request.post(
        `${solandBaseUrl()}/_cokret/self/webrtc/sessions/${encodeURIComponent(sessionId)}/signals`,
        {
          headers: authHeaders(token),
          data: {
            message_type: "ice",
            seq: 1,
            payload: { candidate: "rollback" },
            proofs: [deviceProof()],
          },
        },
      );
      await expectCallSignalError(rollback, 400, "invalid_param");

      const events = await getCallSignals(request, token, sessionId);
      expect(events.map((event) => event.seq)).toEqual([1, 2]);
    } finally {
      await closeCallSession(request, token, sessionId);
    }
  });

  test("future seq gap is rejected and does not consume a cursor", async ({
    request,
  }) => {
    const token = await demoAliceToken(request);
    const sessionId = await createCallSession(request, token);
    try {
      await postCallSignal(request, token, sessionId, "offer", 1, {
        sdp: "v=0",
      });

      const gap = await request.post(
        `${solandBaseUrl()}/_cokret/self/webrtc/sessions/${encodeURIComponent(sessionId)}/signals`,
        {
          headers: authHeaders(token),
          data: {
            message_type: "answer",
            seq: 99,
            payload: { sdp: "gap" },
            proofs: [deviceProof()],
          },
        },
      );
      await expectCallSignalError(gap, 400, "invalid_param");

      const next = await postCallSignal(
        request,
        token,
        sessionId,
        "answer",
        2,
        { sdp: "v=0" },
      );
      expect(next.seq).toBe(2);
    } finally {
      await closeCallSession(request, token, sessionId);
    }
  });
});
