import { expect, type APIRequestContext } from "@playwright/test";
import { accountActorId, scanRealmStreamApi, signedEventEnvelope, submitSignedEventApi } from "./coland-api";
import type { DpopUserSession } from "./users";

// Metadata-free discussion Strands provide real, independently committed
// history without manufacturing encrypted Card content or repeatedly listing
// the Realm inventory. The Card under test is authored afterwards by Inkson.
export async function seedKanbanHistory(
  request: APIRequestContext,
  session: DpopUserSession,
  realmId: string,
) {
  const eventIds = new Set<string>();
  let lastPosition = -1;
  let previousTimestamp = 0;
  for (let index = 0; index < 501; index += 1) {
    previousTimestamp = Math.max(Date.now(), previousTimestamp + 1);
    const createdAt = new Date(previousTimestamp).toISOString();
    const event = signedEventEnvelope({ actorId: session.user.id, realmId,
      kind: "ak.strand.create", createdAt,
      payload: { object: { schema: "ak.schema.strand.v1", realm_id: realmId,
        tracks: { discussion: { enabled: true, is_primary: true, profile: "discussion" } },
        created_by: accountActorId(session.user.id), created_at: createdAt } },
    });
    const outcome = await submitSignedEventApi(request, session.grantJwt, event,
      { context: `history Strand ${index + 1}/501` });
    const commit = outcome.commit as Record<string, unknown>;
    const position = Number(commit.stream_position);
    expect(position).toBeGreaterThan(lastPosition);
    lastPosition = position;
    eventIds.add(String(event.event_id));
  }
  expect(eventIds.size).toBe(501);
  return { inserted_events: eventIds.size, last_seed_position: lastPosition };
}

export async function proveKanbanHistoryTail(
  request: APIRequestContext,
  session: DpopUserSession,
  realmId: string,
  latestCardEventId: string,
  preJoinCreate?: { eventId: string; streamPosition: number },
) {
  const first = await scanRealmStreamApi(request, session.grantJwt, realmId, { limit: 500 });
  expect(first.commits).toHaveLength(500);
  expect(first.truncated).toBe(true);
  expect(first.events.some(event => event?.event_id === latestCardEventId)).toBe(false);
  const afterPosition = Number(first.commits.at(-1)!.stream_position);
  expect(Number.isSafeInteger(afterPosition)).toBe(true);
  if (preJoinCreate) {
    expect(preJoinCreate.streamPosition).toBeLessThan(afterPosition);
    expect(first.events.some(event => event?.event_id === preJoinCreate.eventId)).toBe(false);
  }
  const tail = await scanRealmStreamApi(request, session.grantJwt, realmId,
    { limit: 500, afterPosition });
  expect(tail.events.some(event => event?.event_id === latestCardEventId)).toBe(true);
  expect(tail.commits.every(commit => Number(commit.stream_position) > afterPosition)).toBe(true);
  return { first_page_commits: first.commits.length, first_page_truncated: true,
    next_page_after_position: afterPosition, tail_commits: tail.commits.length,
    latest_card_event_id: latestCardEventId, latest_card_is_after_first_page: true,
    pre_join_create_not_disclosed: preJoinCreate ? true : null };
}
