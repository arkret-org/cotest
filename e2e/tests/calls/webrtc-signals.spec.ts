// WebRTC signal type coverage.
// Contract: e2e/scenarios/calls/webrtc-signals.md

import { expect, test } from "@playwright/test";
import {
  CALL_SIGNAL_TYPES,
  DEMO_ALICE_DID,
  closeCallSession,
  createCallSession,
  demoAliceToken,
  getCallSignals,
  postCallSignal,
} from "../../helpers/webrtc";

test.describe("ck.call.signal v2 signal catalog", () => {
  for (const signalType of CALL_SIGNAL_TYPES) {
    test(`${signalType} stores monotonic seq and device_proof`, async ({
      request,
    }) => {
      const token = await demoAliceToken(request);
      const sessionId = await createCallSession(request, token);
      try {
        const appended = await postCallSignal(
          request,
          token,
          sessionId,
          signalType,
          1,
          {
            signal_type: signalType,
            fixture: "cotest-signal-catalog",
          },
        );
        expect(appended.seq).toBe(1);
        expect(appended.next_cursor).toBe("1");

        const events = await getCallSignals(request, token, sessionId);
        expect(events).toHaveLength(1);
        expect(events[0].seq).toBe(1);
        expect(events[0].type).toBe(signalType);
        expect(events[0].sender).toBe(DEMO_ALICE_DID);
        expect(events[0].device_proof).toMatchObject({ actor: DEMO_ALICE_DID });
      } finally {
        await closeCallSession(request, token, sessionId);
      }
    });
  }
});
