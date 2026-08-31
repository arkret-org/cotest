import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  advanceEnvelopeToActorFrontier,
  eventActorId,
  refreshEventEnvelopeProof,
  registerEventSigner,
  sdkEventDerivedIds,
  serviceActorId,
  signedEventEnvelope,
  typedId,
} from "../../helpers/soland-api";

test("Event Actor identity survives SDK proof refresh and exact frontier selection @fixture-only", async () => {
  const principal = "ak:did_core:web:actor-fixture.example";
  const stationA = "ak:did_core:web:station-a.example";
  const stationB = "ak:did_core:web:station-b.example";
  const method = "did:web:actor-fixture.example#device";
  registerEventSigner({
    actorId: principal,
    deviceId: "ak:device:01904100-0000-7000-8000-0000000000a1",
    verificationMethod: method,
    signingSeedB64url: Buffer.alloc(32, 7).toString("base64url"),
  });
  const args = {
    actorId: principal,
    realmId: typedId("realm"),
    kind: "ak.invite.create",
    actorSeq: 0,
    createdAt: "2026-08-31T00:00:00.000Z",
    hlc: `${Date.parse("2026-08-31T00:00:00.000Z").toString(16).padStart(12, "0")}-0000-01234567`,
    payload: {
      invitee_account_id: { principal_id: principal, station_id: stationA },
      introduction_evidence_digest: `sha256:${"00".repeat(32)}`,
      expires_at: "2026-09-01T00:00:00.000Z",
    },
  };
  const event = signedEventEnvelope({ ...args, stationId: stationA });
  const anotherAccount = signedEventEnvelope({ ...args, stationId: stationB });
  expect(event).not.toHaveProperty("station_id");
  expect(eventActorId(event)).toEqual({
    kind: "account",
    account_id: { principal_id: principal, station_id: stationA },
  });
  expect(anotherAccount.event_id).not.toBe(event.event_id);
  expect(() => eventActorId({ actor_id: principal, station_id: stationA })).toThrow();

  const originalId = event.event_id;
  event.actor_seq = 1;
  event.prev_refs = [originalId];
  refreshEventEnvelopeProof(event, method);
  expect(event.event_id).not.toBe(originalId);
  expect(event.event_id).toBe(sdkEventDerivedIds(event).event_id);

  const service = "ak:did_core:web:service-fixture.example";
  const serviceMethod = "did:web:service-fixture.example#service-key";
  registerEventSigner({
    actorId: service,
    deviceId: "ak:device:01904100-0000-7000-8000-0000000000a2",
    verificationMethod: serviceMethod,
    signingSeedB64url: Buffer.alloc(32, 8).toString("base64url"),
  });
  const delegated = signedEventEnvelope({
    ...args,
    stationId: stationA,
    executedBy: serviceActorId(service),
    authorizationRef: "ak:cell:ak.component.realm.authority_root.v1:null",
  });
  expect(delegated.actor_id).toEqual(event.actor_id);
  expect(delegated.executed_by).toEqual(serviceActorId(service));
  expect((delegated.proofs as Array<Record<string, unknown>>)[0].verification_method).toBe(serviceMethod);
  const delegatedId = delegated.event_id;
  delegated.actor_seq = 3;
  refreshEventEnvelopeProof(delegated);
  expect(delegated.event_id).not.toBe(delegatedId);
  expect((delegated.proofs as Array<Record<string, unknown>>)[0].verification_method).toBe(serviceMethod);

  let selected: Record<string, unknown> | undefined;
  const request = {
    async fetch(_url: string, options: { data: string }) {
      selected = JSON.parse(options.data);
      const body = {
        frontier: {
          kind: "realm_actor", realm_id: args.realmId,
          actor_id: structuredClone(event.actor_id),
          next_actor_seq: 2, frontier_event_ids: [event.event_id],
        },
      };
      return {
        status: () => 200,
        ok: () => true,
        text: async () => JSON.stringify(body),
        json: async () => body,
      };
    },
  } as unknown as APIRequestContext;
  const previousBase = process.env.COTEST_SOLAND_BASE_URL;
  process.env.COTEST_SOLAND_BASE_URL ??= "http://station-fixture.example";
  try {
    await advanceEnvelopeToActorFrontier(request, "fixture-token", event);
  } finally {
    if (previousBase === undefined) delete process.env.COTEST_SOLAND_BASE_URL;
    else process.env.COTEST_SOLAND_BASE_URL = previousBase;
  }
  expect(selected?.actor_id).toEqual(event.actor_id);
  expect(event.actor_seq).toBe(2);
  expect(event.event_id).toBe(sdkEventDerivedIds(event).event_id);
});
