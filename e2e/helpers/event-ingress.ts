// One typed decoder for everything a test observes on Event ingress.
//
// `POST /_arkret/self/events` carries either one `EventInitialSubmission` or an
// `EventsSubmitBatchRequestBody`, whose `events[]` contain that same wrapper —
// not bare Events (`arkret-rust-sdk/crates/wire/src/event_submission.rs`).
// Every listener that reached into `events[0].kind` directly kept working right
// up to the moment the wire shape moved, and then reported "no request" for a
// submission the server had actually accepted.
//
// So the canonical shape is the only one accepted by default. A caller that is
// deliberately straddling a migration passes `allowBareEvents`, and anything
// else raises here — once, in one place — instead of turning into a silently
// empty result set in whichever scenario happened to look first.

export type IngressEvent = Record<string, unknown> & {
  event_id?: string;
  kind?: string;
  realm_id?: string;
  actor_id?: string;
  actor_seq?: number;
  prev_refs?: string[];
  payload?: Record<string, unknown>;
};

export type IngressSubmission = {
  event: IngressEvent;
  authorization_lease?: Record<string, unknown>;
  cba_proof_bundles?: unknown[];
  control_proposal_receipt?: Record<string, unknown>;
};

export type IngressDecodeOptions = {
  /// Accept a bare Event where the canonical wrapper is expected. Only for a
  /// listener that must span a wire migration; it is never the default.
  allowBareEvents?: boolean;
  /// Prefix for the thrown message, so a failure names the listener.
  context?: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function decodeSubmission(
  candidate: unknown,
  index: number,
  options: IngressDecodeOptions,
): IngressSubmission {
  const where = `${options.context ?? "Event ingress"} events[${index}]`;
  if (!isRecord(candidate)) {
    throw new Error(`${where} is not an object`);
  }
  if (isRecord(candidate.event)) {
    return candidate as IngressSubmission;
  }
  if (options.allowBareEvents && typeof candidate.kind === "string") {
    return { event: candidate as IngressEvent };
  }
  throw new Error(
    `${where} is not an EventInitialSubmission: expected a nested "event", ` +
      `got keys [${Object.keys(candidate).join(", ")}]`,
  );
}

/// Decode an already-parsed single or batch initial-publication request.
export function decodeEventIngressBody(
  body: unknown,
  options: IngressDecodeOptions = {},
): IngressSubmission[] {
  if (!isRecord(body)) {
    throw new Error(`${options.context ?? "Event ingress"} body is not an object`);
  }
  if (Array.isArray(body.events)) {
    return body.events.map((candidate, index) =>
      decodeSubmission(candidate, index, options),
    );
  }
  if (isRecord(body.event)) {
    return [decodeSubmission(body, 0, options)];
  }
  throw new Error(
    `${options.context ?? "Event ingress"} body is neither a single ` +
      `EventInitialSubmission nor an events[] batch`,
  );
}

/// Decode a captured request body. Non-JSON traffic is not Event ingress and
/// yields an empty batch; a JSON body with the wrong shape still raises.
export function decodeEventIngressPostData(
  postData: string | null | undefined,
  options: IngressDecodeOptions = {},
): IngressSubmission[] {
  if (!postData) return [];
  let body: unknown;
  try {
    body = JSON.parse(postData);
  } catch {
    return [];
  }
  return decodeEventIngressBody(body, options);
}

/// The signed Events of one batch, without their publication evidence.
export function ingressEvents(
  submissions: IngressSubmission[],
): IngressEvent[] {
  return submissions.map((submission) => submission.event);
}

/// Convenience for listeners that only want the signed Events of a request.
export function decodeIngressEvents(
  postData: string | null | undefined,
  options: IngressDecodeOptions = {},
): IngressEvent[] {
  return ingressEvents(decodeEventIngressPostData(postData, options));
}
