// Shared /inspect middleware for cotest mocks.
//
// Mocks instantiate one InspectLog per "kind" of event they want to expose
// to scenario specs (e.g. tokens, inboxes, signatures) and pass the logs
// into `handleInspect(req, res, logs)`. Specs hit GET /inspect to receive
// a JSON dump:
//
//   { service, started_at, now, kinds: { token: [...], signed: [...] } }
//
// The log is bounded (default 500 entries) so a long-running harness does
// not retain unbounded history. Old entries are dropped FIFO.

const DEFAULT_LIMIT = 500;

export class InspectLog {
  constructor(kind, { limit = DEFAULT_LIMIT } = {}) {
    this.kind = kind;
    this.limit = limit;
    this.entries = [];
  }

  record(entry) {
    this.entries.push({
      at: new Date().toISOString(),
      ...entry,
    });
    if (this.entries.length > this.limit) {
      this.entries.splice(0, this.entries.length - this.limit);
    }
  }

  clear() {
    this.entries.length = 0;
  }
}

export function handleInspect(req, res, { service, logs, extra = {} }) {
  const url = new URL(req.url, "http://127.0.0.1");
  if (req.method === "DELETE") {
    for (const log of logs) log.clear();
    res.statusCode = 200;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ ok: true, cleared: logs.map((l) => l.kind) }));
    return true;
  }
  if (req.method === "GET") {
    const kindFilter = url.searchParams.get("kind");
    const kinds = {};
    for (const log of logs) {
      if (!kindFilter || kindFilter === log.kind) {
        kinds[log.kind] = log.entries;
      }
    }
    res.statusCode = 200;
    res.setHeader("content-type", "application/json");
    res.end(
      JSON.stringify({
        service,
        now: new Date().toISOString(),
        kinds,
        ...extra,
      }),
    );
    return true;
  }
  return false;
}
