import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { cotestWire, runCotestWireJsonProcess } from "../helpers/coland-api/wire-client.ts";

function withPrivateScratch(body) {
  const scratch = mkdtempSync(join(tmpdir(), "oracle-stdin-unit-"));
  const previous = process.env.TMPDIR;
  process.env.TMPDIR = scratch;
  try {
    const result = body(scratch);
    assert.deepEqual(readdirSync(scratch), [], "all staged input must be removed");
    return result;
  } finally {
    if (previous === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = previous;
    rmSync(scratch, { recursive: true, force: true });
  }
}
const digest = bytes => createHash("sha256").update(bytes).digest("hex");
const execute = (script, input, timeoutMs) => runCotestWireJsonProcess(process.execPath,
  ["-e", script], input, { cwd: process.cwd(), ...(timeoutMs === undefined ? {} : { timeoutMs }) });

test("native EOF is finite, UTF8 bytes are exact and input/directory are private", () => withPrivateScratch(() => {
  const input = JSON.stringify({ value: "unicode-é-😀\n".repeat(20_000) });
  const result = execute(`const fs=require('node:fs'),crypto=require('node:crypto'),os=require('node:os'),path=require('node:path');
    const stat=fs.fstatSync(0), bytes=fs.readFileSync(0);
    const scratch=fs.readdirSync(os.tmpdir()).find(name=>name.startsWith('cotest-wire-json-'));
    console.log(JSON.stringify({regular:stat.isFile(),mode:stat.mode&511,dirMode:fs.statSync(path.join(os.tmpdir(),scratch)).mode&511,
      length:bytes.length,sha256:crypto.createHash('sha256').update(bytes).digest('hex')}));`, input);
  assert.equal(result.status, 0); assert.equal(result.error, undefined);
  const observed = JSON.parse(result.stdout);
  assert.equal(observed.regular, true); assert.equal(observed.length, Buffer.byteLength(input));
  assert.equal(observed.sha256, digest(input));
  if (process.platform !== "win32") { assert.equal(observed.mode, 0o600); assert.equal(observed.dirMode, 0o700); }
}));

test("a real prebuilt SDK oracle hashes input larger than the unchanged stdout limit", () => withPrivateScratch(() => {
  assert.ok(process.env.COTEST_WIRE_BIN, "real prebuilt oracle is required; never use Cargo in this test");
  const value = { payload: "unicode-é-😀".repeat(1_100_000) };
  const input = JSON.stringify({ value });
  assert.ok(Buffer.byteLength(input) > 10 * 1024 * 1024);
  const result = cotestWire("sha256-canonical-json", { value });
  assert.equal(result.digest_hex, digest(JSON.stringify(value)));
}));

test("native nonzero status is preserved without copying private input into stderr", () => withPrivateScratch(() => {
  const marker = "private-input-must-not-be-logged";
  const result = execute("require('node:fs').readFileSync(0);console.error('intentional-native-fixture-failure');process.exitCode=7", marker);
  assert.equal(result.status, 7); assert.equal(result.error, undefined);
  assert.match(result.stderr, /intentional-native-fixture-failure/); assert.equal(result.stderr.includes(marker), false);
}));

test("a missing executable preserves ENOENT and removes its staged input", () => withPrivateScratch(scratch => {
  const result = runCotestWireJsonProcess(join(scratch, "absent-oracle"), [], "private-input", { cwd: process.cwd() });
  assert.equal(result.error?.code, "ENOENT");
}));

test("a nonterminating native child is bounded and staged input is removed", () => withPrivateScratch(() => {
  const started = Date.now();
  const result = execute("process.stdin.resume();setInterval(()=>{},1000)", "private-input", 200);
  assert.equal(result.error?.code, "ETIMEDOUT"); assert.ok(Date.now() - started < 5000);
}));

test("the original10MiB stdout limit still refuses oversized native output", () => withPrivateScratch(() => {
  const result = execute("require('node:fs').readFileSync(0);process.stdout.write(Buffer.alloc(10*1024*1024+65536,120))", "{}", 10_000);
  assert.equal(result.error?.code, "ENOBUFS");
}));
