import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import test from "node:test";

test("recipient-scoped actual 503 preserves private attempted inbox and normal mail", async () => {
  const child = spawn(process.execPath, [new URL("./mock-email.mjs", import.meta.url).pathname], {
    env: { ...process.env, MOCK_EMAIL_PORT: "0" }, stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  const base = await new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error("mock startup timeout")), 10_000);
    child.stdout.on("data", bytes => { output += bytes.toString(); });
    child.stderr.on("data", bytes => {
      output += bytes.toString();
      const match = output.match(/listening on (http:\/\/127\.0\.0\.1:\d+)/);
      if (match) { clearTimeout(deadline); resolve(match[1]); }
    });
    child.once("error", error => { clearTimeout(deadline); reject(error); });
  });
  const request = async (path, body, method = "POST") => fetch(`${base}${path}`, {
    method, headers: { "content-type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const control = enabled => request("/inspect", { delivery_failure: { to: "fault@example.test", enabled } });
  const send = (to, token) => request("/mock/email/verification/send", { to, token, body: `Private synthetic body ${token}` });
  try {
    const ack = await (await control(true)).json();
    assert.equal(JSON.stringify(ack).includes("fault@example.test"), false);
    assert.equal(ack.configured, true);
    for (let i = 0; i < 3; i++) assert.equal((await send("fault@example.test", `synthetic-private-${i}`)).status, 503);
    const failed = await (await request("/mock/email/verification/inbox?to=fault%40example.test", undefined, "GET")).json();
    assert.equal(failed.messages.length, 3);
    assert.equal(failed.messages.every(message => message.delivery_status === "failed" && message.body.startsWith("Private synthetic body")), true);
    const global = await (await request("/inspect", undefined, "GET")).json();
    assert.equal(JSON.stringify(global).includes("synthetic-private-"), false);
    assert.equal((await request("/mock/email/verification/claim", { token: "synthetic-private-0", did: "synthetic-subject" })).status, 404);
    assert.equal((await send("healthy@example.test", "synthetic-delivered")).status, 200);
    const healthy = await (await request("/mock/email/verification/inbox?to=healthy%40example.test", undefined, "GET")).json();
    assert.equal(healthy.messages.length, 1);
    assert.equal(healthy.messages[0].delivery_status, "delivered");
    assert.equal((await request("/inspect", { delivery_failure: { to: "healthy@example.test", enabled: "yes" } })).status, 400);
    await control(false);
    assert.equal((await send("fault@example.test", "synthetic-recovered")).status, 200);
    await control(true);
    assert.equal((await request("/inspect", undefined, "DELETE")).status, 200);
    assert.equal((await send("fault@example.test", "synthetic-after-clear")).status, 200);
    assert.equal(output.includes("synthetic-private-"), false);
    assert.equal(output.includes("fault@example.test"), false);
    assert.equal(output.includes("Private synthetic body"), false);
  } finally {
    const exited = once(child, "exit");
    child.kill("SIGTERM");
    await exited;
  }
});
