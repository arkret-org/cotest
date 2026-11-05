import type { CDPSession, Page } from "@playwright/test";

type PublicSignalArrival = {
  envelope_digest: string; sent_at_ms: number; expires_at_ms: number;
  cdp_timestamp_ms: number; callback_at_ms: number;
};
const object = (value: unknown): Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : {};

// Passive transport arrival, separate from authenticated admission. Never
// retain a frame body, ciphertext, delivery authority, URL, header or proof.
export async function observeSignalTransport(page: Page, realm: string) {
  let session: CDPSession;
  try { session = await page.context().newCDPSession(page); }
  catch { return async () => ({ available: false as const }); }
  const arrivals: PublicSignalArrival[] = [];
  const httpChunks: Array<{ cdp_timestamp_ms: number; callback_at_ms: number }> = [];
  const streams = new Set<string>();
  let offset: { lower: number; upper: number; source: "performance" | "network" } | null = null;
  let signalCount = 0;
  let chunkCount = 0;
  const metricNames = ["TaskDuration", "ScriptDuration", "LayoutDuration", "RecalcStyleDuration"];
  let initialMetrics = new Map<string, number>();
  let profiling = false;
  const counters = (metrics: Array<{ name: string; value: number }>) => new Map(metrics
    .filter(value => metricNames.includes(value.name) && finite(value.value))
    .map(value => [value.name, value.value]));
  const finite = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);
  const anchor = (event: unknown) => {
    const value = object(event);
    if (finite(value.timestamp) && finite(value.wallTime)) {
      const exact = (value.wallTime - value.timestamp) * 1000;
      offset = { lower: exact, upper: exact, source: "network" };
    }
  };
  const frame = (event: unknown) => {
    const value = object(event);
    const response = object(value.response);
    if (response.opcode !== 1 || typeof response.payloadData !== "string"
      || response.payloadData.length > 64 * 1024 || !finite(value.timestamp)) return;
    try {
      const outer = object(JSON.parse(response.payloadData));
      const payload = object(outer.payload);
      if (outer.kind !== "data" || payload.kind !== "signal") return;
      const envelope = object(payload.envelope);
      const proof = object(envelope.proof);
      const stamp = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
      if (envelope.realm_id !== realm || typeof proof.envelope_digest !== "string"
        || !/^sha256:[a-f0-9]{64}$/.test(proof.envelope_digest)
        || typeof envelope.sent_at !== "string" || !stamp.test(envelope.sent_at)
        || typeof envelope.expires_at !== "string" || !stamp.test(envelope.expires_at)) return;
      const sent = Date.parse(envelope.sent_at), expires = Date.parse(envelope.expires_at);
      if (!Number.isFinite(sent) || !Number.isFinite(expires)) return;
      signalCount++;
      if (arrivals.length < 64) arrivals.push({ envelope_digest: proof.envelope_digest,
        sent_at_ms: sent, expires_at_ms: expires, cdp_timestamp_ms: value.timestamp * 1000,
        callback_at_ms: Date.now() });
    } catch { /* Malformed frames supply no timing evidence. */ }
  };
  const response = (event: unknown) => {
    const value = object(event), response = object(value.response);
    if (typeof value.requestId !== "string" || typeof response.url !== "string") return;
    try {
      if (new URL(response.url).pathname === "/_arkret/self/signal/subscribe" && streams.size < 16)
        streams.add(value.requestId);
    } catch { /* No arbitrary transport value is retained. */ }
  };
  const chunk = (event: unknown) => {
    const value = object(event);
    if (typeof value.requestId !== "string" || !streams.has(value.requestId) || !finite(value.timestamp)) return;
    chunkCount++;
    if (httpChunks.length < 64) httpChunks.push({ cdp_timestamp_ms: value.timestamp * 1000, callback_at_ms: Date.now() });
  };
  session.on("Network.requestWillBeSent", anchor);
  session.on("Network.webSocketFrameReceived", frame);
  session.on("Network.responseReceived", response);
  session.on("Network.dataReceived", chunk);
  try {
    await session.send("Network.enable");
    await session.send("Performance.enable");
    const start = Date.now();
    const metrics = await session.send("Performance.getMetrics");
    initialMetrics = counters(metrics.metrics ?? []);
    const end = Date.now();
    const stamp = metrics.metrics?.find((metric: { name: string }) => metric.name === "Timestamp")?.value;
    if (!offset && finite(stamp)) offset = { lower: start - stamp * 1000,
      upper: end - stamp * 1000, source: "performance" };
    try {
      await session.send("Profiler.enable");
      await session.send("Profiler.start");
      profiling = true;
    } catch { /* Transport timing remains available without CPU sampling. */ }
  } catch {
    await session.detach().catch(() => {});
    return async () => ({ available: false as const });
  }
  return async () => {
    session.off("Network.requestWillBeSent", anchor);
    session.off("Network.webSocketFrameReceived", frame);
    session.off("Network.responseReceived", response);
    session.off("Network.dataReceived", chunk);
    let rendererWork: Record<string, number | null> | null = null;
    let wasmSampling: { total_samples: number; wasm_samples: number;
      hotspots: Array<{ module: number; code_offset: number; samples: number }> } | null = null;
    if (profiling) {
      try {
        const { profile } = await session.send("Profiler.stop");
        const modules = new Map<string, number>();
        const nodes = new Map<number, { module: number; code_offset: number }>();
        for (const node of profile.nodes) {
          const frame = node.callFrame;
          if (!/^wasm:\/\/wasm\/[a-f0-9]+$/i.test(frame.url)
            || !Number.isSafeInteger(frame.columnNumber) || frame.columnNumber < 0) continue;
          if (!modules.has(frame.url)) modules.set(frame.url, modules.size + 1);
          nodes.set(node.id, { module: modules.get(frame.url)!, code_offset: frame.columnNumber });
        }
        const counts = new Map<string, { module: number; code_offset: number; samples: number }>();
        let wasmSamples = 0;
        for (const sample of profile.samples ?? []) {
          const node = nodes.get(sample);
          if (!node) continue;
          wasmSamples++;
          const key = `${node.module}:${node.code_offset}`;
          const entry = counts.get(key) ?? { ...node, samples: 0 };
          entry.samples++;
          counts.set(key, entry);
        }
        // Function names, script URLs, JS frames and the raw profile never
        // leave this projection. Offsets require the exact served WASM map.
        wasmSampling = { total_samples: profile.samples?.length ?? 0, wasm_samples: wasmSamples,
          hotspots: [...counts.values()].sort((a, b) => b.samples - a.samples).slice(0, 64) };
      } catch { /* An unavailable profile does not replace a business failure. */ }
    }
    try {
      const metrics = await session.send("Performance.getMetrics");
      const final = counters(metrics.metrics ?? []);
      rendererWork = Object.fromEntries(metricNames.map(name => [name,
        initialMetrics.has(name) && final.has(name) && final.get(name)! >= initialMetrics.get(name)!
          ? (final.get(name)! - initialMetrics.get(name)!) * 1000 : null]));
    } catch { /* A closed renderer contributes no work counters. */ }
    await session.detach().catch(() => {});
    const project = (value: { cdp_timestamp_ms: number; callback_at_ms: number }) => ({
      callback_at_ms: value.callback_at_ms,
      arrival_lower_ms: offset ? value.cdp_timestamp_ms + offset.lower : null,
      arrival_upper_ms: offset ? value.cdp_timestamp_ms + offset.upper : null,
    });
    return { available: true as const, clock_source: offset?.source ?? "unavailable",
      clock_uncertainty_ms: offset ? offset.upper - offset.lower : null,
      renderer_work_ms: rendererWork,
      wasm_sampling: wasmSampling,
      signal_count: signalCount, http_chunk_count: chunkCount,
      truncated: signalCount > 64 || chunkCount > 64,
      signals: arrivals.map(value => ({ envelope_digest: value.envelope_digest,
        sent_at_ms: value.sent_at_ms, expires_at_ms: value.expires_at_ms, ...project(value) })),
      // Chunks cannot identify an individual Signal; never claim correlation.
      uncorrelated_http_chunks: httpChunks.map(project) };
  };
}
