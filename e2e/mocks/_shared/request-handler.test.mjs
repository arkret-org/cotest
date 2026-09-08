import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { isolateRequestFailure } from "./request-handler.mjs";

test("rejected requests return 500 without breaking subsequent requests", async () => {
  const server = createServer(isolateRequestFailure(async (req, res) => {
    if (req.url === "/fail") throw new Error("private fixture material");
    res.end("ready");
  }));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const failed = await fetch(`${base}/fail`);
    assert.equal(failed.status, 500);
    assert.deepEqual(await failed.json(), { error: "mock_request_failed" });
    const healthy = await fetch(`${base}/health`);
    assert.equal(healthy.status, 200);
    assert.equal(await healthy.text(), "ready");
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
