import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

// Execute the exact production inline module in real browser tabs. This tests
// Web Locks/storage, not native Station authority or the complete UI journey.
const rust = readFileSync(new URL("../../../../inkson/src/signal.rs", import.meta.url), "utf8");
const inline = [...rust.matchAll(/inline_js = r#"([\s\S]*?)"#/g)]
  .map((match) => match[1])
  .find((source) => source.includes("export async function reserveSignalSequenceBlock"));
if (!inline) throw new Error("production Signal counter module is missing");
const sourceDigest = createHash("sha256").update(inline).digest("hex");
const origin = "http://localhost:47991";

declare global {
  interface Window {
    reserveSignalCounter: (
      key: string, block: bigint, minimum: bigint, allowMissing: boolean,
    ) => Promise<string>;
  }
}

async function install(page: Page): Promise<void> {
  await page.route(`${origin}/**`, (route) => route.fulfill({ contentType: "text/html", body: "<!doctype html><title>Signal counter backend</title>" }));
  await page.goto(origin);
  await loadModule(page);
}

async function loadModule(page: Page): Promise<void> {
  await page.evaluate(async (source) => {
    const url = URL.createObjectURL(new Blob([source], { type: "text/javascript" }));
    const module = await import(url);
    window.reserveSignalCounter = module.reserveSignalSequenceBlock;
    URL.revokeObjectURL(url);
  }, inline!);
}

test.beforeEach(() => {
  test.info().annotations.push({ type: "production-js-sha256", description: sourceDigest });
});

test("two real tabs reserve disjoint nonces and reload continues the committed high-water", async ({ context }) => {
  const first = await context.newPage();
  const second = await context.newPage();
  await Promise.all([install(first), install(second)]);
  const key = "inkson.signal_sequence.v1.fixture.nonce:shared";
  const reserve = (page: Page) => page.evaluate(async (key) => Promise.all(
    Array.from({ length: 24 }, () => window.reserveSignalCounter(key, 1n, 0n, true)),
  ), key);
  const allocated = (await Promise.all([reserve(first), reserve(second)])).flat().map(Number).sort((a, b) => a - b);
  expect(allocated).toEqual(Array.from({ length: 48 }, (_, index) => index));
  await first.reload();
  await loadModule(first);
  expect(await first.evaluate((key) => window.reserveSignalCounter(key, 1n, 48n, false), key)).toBe("48");
});

test("missing, rolled-back, corrupt and exhausted allocators fail closed", async ({ page }) => {
  await install(page);
  const outcomes = await page.evaluate(async () => {
    const key = "inkson.signal_sequence.v1.fixture.nonce:lost";
    const reserve = (minimum: bigint) => window.reserveSignalCounter(key, 1n, minimum, false);
    const failures: string[] = [];
    for (const [encoded, minimum] of [[null, 1n], ["1", 2n], ["-1", 0n], ["01", 0n], ["18446744073709551615", 0n]] as const) {
      if (encoded === null) localStorage.removeItem(key);
      else localStorage.setItem(key, encoded);
      try { await reserve(minimum); failures.push("accepted"); }
      catch (error) { failures.push(String(error)); }
    }
    return failures;
  });
  expect(outcomes[0]).toContain("missing");
  expect(outcomes[1]).toContain("rolled back");
  expect(outcomes[2]).toContain("corrupt");
  expect(outcomes[3]).toContain("corrupt");
  expect(outcomes[4]).toContain("exhausted");
});

test("endpoint nonce domains remain independent of business sequence domains", async ({ page }) => {
  await install(page);
  const values = await page.evaluate(async () => {
    const reserve = window.reserveSignalCounter;
    const prefix = "inkson.signal_sequence.v1.fixture.";
    return [
      await reserve(`${prefix}nonce:phone`, 1n, 0n, true),
      await reserve(`${prefix}nonce:laptop`, 1n, 0n, true),
      await reserve(`${prefix}business`, 256n, 1n, true),
      await reserve(`${prefix}nonce:phone`, 1n, 1n, false),
      await reserve(`${prefix}business`, 256n, 1n, true),
    ];
  });
  expect(values).toEqual(["0", "0", "1", "1", "257"]);
});
