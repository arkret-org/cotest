import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import { chromium } from "@playwright/test";
import { revealTimelineEvent, sampleAndAdvanceTimeline } from "../helpers/timeline-visibility.ts";

let browser;
before(async () => { browser = await chromium.launch(); });
after(async () => { await browser?.close(); });

const layoutSource = readFileSync(new URL("../../../inkson/src/views/chat/timeline_window.js", import.meta.url), "utf8");

async function fixture(page) {
  await page.setContent(`<div data-testid="message-list" style="height:200px;overflow:auto">
    <div id="rows" style="position:relative"></div></div>`);
  await page.addScriptTag({ content: layoutSource });
  await page.evaluate(() => {
    const keys = Array.from({ length: 30 }, (_, index) => `row-${index}`);
    const layout = new TimelineLayout(keys, new Map(keys.map(key => [key, 400])));
    const feed = document.querySelector('[data-testid="message-list"]');
    const rows = document.getElementById("rows");
    rows.style.height = `${layout.total()}px`;
    const render = () => {
      const window = layout.window(feed.scrollTop, feed.clientHeight);
      rows.replaceChildren();
      for (let index = window.start; index < window.end; index++) {
        const row = document.createElement("div");
        row.dataset.testid = "chat-message";
        row.textContent = keys[index];
        row.style.cssText = `position:absolute;top:${layout.prefix(index)}px;height:400px`;
        rows.append(row);
      }
    };
    feed.addEventListener("scroll", render);
    feed.scrollTop = feed.scrollHeight;
    render();
  });
}

test("an old unmounted row is revealed by scrolling the real feed", async () => {
  const page = await browser.newPage();
  try {
    await fixture(page);
    const event = page.getByTestId("chat-message").filter({ hasText: /^row-0$/ });
    assert.equal(await event.count(), 0);
    await revealTimelineEvent(page, event, 5_000);
    assert.equal(await event.count(), 1);
    assert.equal(await page.getByTestId("message-list").evaluate(feed => feed.scrollTop), 0);
  } finally { await page.close(); }
});

test("the feed traversal reaches a row between the initial tail and first window", async () => {
  const page = await browser.newPage();
  try {
    await fixture(page);
    const event = page.getByTestId("chat-message").filter({ hasText: /^row-4$/ });
    assert.equal(await event.count(), 0);
    await revealTimelineEvent(page, event, 5_000);
    assert.equal(await event.count(), 1);
  } finally { await page.close(); }
});

test("missing messages remain a failure within the supplied budget", async () => {
  const page = await browser.newPage();
  try {
    await fixture(page);
    const event = page.getByTestId("chat-message").filter({ hasText: "not-accepted" });
    await assert.rejects(revealTimelineEvent(page, event, 500), /timeline action target/);
    assert.equal(await event.count(), 0);
  } finally { await page.close(); }
});

test("sampling advances within the viewport instead of jumping over a provisional overscan tail", async () => {
  const page = await browser.newPage();
  try {
    await page.setContent(`<div data-testid="message-list" style="height:91px;overflow:auto;overflow-anchor:none">
      <div id="rows" style="position:relative;overflow-anchor:none"></div></div>`);
    await page.addScriptTag({ content: layoutSource });
    await page.evaluate(() => {
      const keys = Array.from({ length: 256 }, (_, index) => `row-${index}`);
      const layout = new TimelineLayout(keys);
      const feed = document.querySelector('[data-testid="message-list"]');
      const rows = document.getElementById("rows");
      let frame = 0;
      const render = () => {
        frame = 0;
        const anchor = layout.at(feed.scrollTop);
        const within = feed.scrollTop - layout.prefix(anchor);
        const window = layout.window(feed.scrollTop, feed.clientHeight);
        rows.replaceChildren();
        for (let index = window.start; index < window.end; index++) {
          const row = document.createElement("div");
          row.dataset.virtualIndex = `${index}`;
          row.textContent = keys[index];
          row.style.cssText = `position:absolute;top:${layout.prefix(index)}px;height:${100 + index % 17 * 35}px`;
          rows.append(row);
        }
        // Simulate the production bridge's provisional window before its next
        // measurement frame, not an already fully measured fixed-height list.
        requestAnimationFrame(() => {
          for (const row of rows.children) layout.measure(Number(row.dataset.virtualIndex), row.getBoundingClientRect().height);
          rows.style.height = `${layout.total()}px`;
          for (const row of rows.children) row.style.top = `${layout.prefix(Number(row.dataset.virtualIndex))}px`;
          feed.scrollTop = layout.prefix(anchor) + within;
        });
        rows.style.height = `${layout.total()}px`;
      };
      feed.addEventListener("scroll", () => { if (!frame) frame = requestAnimationFrame(render); });
      render();
    });
    const seen = new Set();
    const feed = page.getByTestId("message-list");
    for (const text of await sampleAndAdvanceTimeline(feed)) seen.add(Number(text.slice(4)));
    const firstTop = await feed.evaluate(element => element.scrollTop);
    assert.ok(firstTop > 0 && firstTop < 200, "the first step must not jump to the overscan tail");
    for (let step = 0; step < 1024 && seen.size < 256; step++) {
      for (const text of await sampleAndAdvanceTimeline(feed)) seen.add(Number(text.slice(4)));
      await page.waitForTimeout(75);
    }
    assert.deepEqual([...seen].sort((a, b) => a - b), Array.from({ length: 256 }, (_, index) => index));
  } finally { await page.close(); }
});
