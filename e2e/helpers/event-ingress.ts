// One typed decoder for everything a test observes on Event ingress.
//
// `POST /_arkret/self/events` carries an EventAdmissionSubmission or a
// registered atomic unit whose events[] contain that same wrapper, or an
// MlsCommitSubmission whose commit_event is the sole shared Event and whose
// welcomes are recipient deliveries in the same authority transaction.
// Every listener that reached into `events[0].kind` directly kept working right
// up to the moment the wire shape moved, and then reported "no request" for a
// submission the server had actually accepted.
//
// The canonical shape is the only accepted shape. Anything else raises here
// — once, in one place — instead of turning into a silently
// empty result set in whichever scenario happened to look first.

export type IngressEvent = Record<string, unknown> & {
  event_id?: string;
  kind?: string;
  realm_id?: string;
  actor_id?: unknown;
  payload?: Record<string, unknown>;
};

export type IngressSubmission = {
  event: IngressEvent;
};

export type IngressDecodeOptions = {
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
  throw new Error(
    `${where} is not an EventAdmissionSubmission: expected a nested "event", ` +
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
    if (!["ordinary_realm_bootstrap", "direct_conversation_founding", "membership_compensation"].includes(String(body.unit_kind))) {
      throw new Error(`${options.context ?? "Event ingress"} has no registered atomic unit_kind`);
    }
    return body.events.map((candidate, index) =>
      decodeSubmission(candidate, index, options),
    );
  }
  if (isRecord(body.event)) {
    return [decodeSubmission(body, 0, options)];
  }
  if (isRecord(body.commit_event)) {
    if (body.commit_event.kind !== "ak.mls.commit" ||
        !Array.isArray(body.welcomes) || typeof body.idempotency_key !== "string") {
      throw new Error(`${options.context ?? "Event ingress"} is not an MlsCommitSubmission`);
    }
    return [{ event: body.commit_event as IngressEvent }];
  }
  throw new Error(
    `${options.context ?? "Event ingress"} body is neither a single ` +
      `EventAdmissionSubmission, MlsCommitSubmission nor a registered atomic unit`,
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
