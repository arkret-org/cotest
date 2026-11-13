import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import { chromium } from "@playwright/test";
import { revealTimelineEvent, sampleAndAdvanceTimeline } from "../helpers/timeline-visibility.ts";

let browser;
before(async () => { browser = await chromium.launch(); });
after(async () => { await browser?.close(); });

const layoutSource = readFileSync(new URL("../../../inkson/src/views/chat/timeline_window.js", import.meta.url), "utf8");

async function loadLayout(page) {
  await page.addScriptTag({ type: "module", content: `${layoutSource}\nglobalThis.TimelineLayout = TimelineLayout;` });
}

async function fixture(page) {
  await page.setContent(`<div class="message-list" data-testid="message-list" style="height:200px;overflow:auto">
    <div id="rows" style="position:relative"></div></div>`);
  await loadLayout(page);
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
        row.className = "chat-message";
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
    await page.setContent(`<div class="message-list" data-testid="message-list" style="height:91px;overflow:auto;overflow-anchor:none">
      <div id="rows" style="position:relative;overflow-anchor:none"></div></div>`);
    await loadLayout(page);
    await page.evaluate(() => {
      const keys = Array.from({ length: 256 }, (_, index) => `row-${index}`);
      const layout = new TimelineLayout(keys);
      const feed = document.querySelector('[data-testid="message-list"]');
      const rows = document.getElementById("rows");
      let frame = 0;
      const render = () => {
        frame = 0;
        const window = layout.window(feed.scrollTop, feed.clientHeight);
        rows.replaceChildren();
        for (let index = window.start; index < window.end; index++) {
          const row = document.createElement("div");
          row.className = "chat-message";
          row.dataset.virtualIndex = `${index}`;
          row.textContent = keys[index];
          row.style.cssText = `position:absolute;top:${layout.prefix(index)}px;height:${100 + index % 17 * 35}px`;
          rows.append(row);
        }
        // Simulate the production bridge's provisional window before its next
        // measurement frame, not an already fully measured fixed-height list.
        requestAnimationFrame(() => {
          // Match the bridge's measurement boundary: preserve the reader's
          // current position, including a scroll since the render frame.
          const anchor = layout.at(feed.scrollTop);
          const within = feed.scrollTop - layout.prefix(anchor);
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

async function intersectsFeed(row, feed) {
  const box = await row.boundingBox();
  const viewport = await feed.boundingBox();
  return !!box && !!viewport && box.y < viewport.y + viewport.height
    && box.y + box.height > viewport.y;
}

test("mounted historical rows must be scrolled into the actual clipped feed", async () => {
  const page = await browser.newPage();
  try {
    await page.setContent(`<div class="message-list" style="height:140px;width:500px;overflow:auto">
      <div style="height:500px"></div>
      <article class="chat-message" id="old-report" style="height:100px">Accepted historical report</article>
      <div style="height:700px">Large poster</div></div>`);
    const feed = page.locator(".message-list");
    const row = page.locator("#old-report");
    assert.equal(await row.count(), 1);
    assert.equal(await intersectsFeed(row, feed), false);
    await revealTimelineEvent(page, row, 5_000, feed);
    assert.equal(await intersectsFeed(row, feed), true,
      "finding an offscreen DOM node is insufficient");
  } finally { await page.close(); }
});

test("a cold production virtual timeline keeps the requested historical row readable", async () => {
  const page = await browser.newPage();
  try {
    await page.setContent(`<style>
      .message-list{height:140px;width:500px;overflow:auto;display:flex;flex-direction:column;position:relative}
      .virtual-timeline{position:relative;flex-shrink:0}
      .chat-virtual-slice{position:absolute;width:100%;display:flex;flex-direction:column;gap:12px}
      .chat-message{flex-shrink:0}
      </style><div id="feed" class="message-list"><div class="virtual-timeline">
      <div class="chat-virtual-slice"></div></div></div>`);
    await page.evaluate(async source => {
      const module = await import(URL.createObjectURL(new Blob([source], { type: "text/javascript" })));
      const keys = Array.from({ length: 16 }, (_, index) => String(index));
      const list = document.querySelector(".virtual-timeline");
      const slice = document.querySelector(".chat-virtual-slice");
      const render = (start, end, top = 0) => {
        slice.style.top = `${top}px`;
        slice.innerHTML = keys.slice(start, end).map(key =>
          `<article class="chat-message chat-message-row" id="chat-message-${key}" `
          + `style="height:${key === "15" ? 640 : 120}px">Report ${key}</article>`).join("");
      };
      list.style.height = `${keys.length * 132}px`;
      render(0, keys.length);
      let controller;
      controller = module.mountVirtualTimeline({ feed_id: "feed", follows_latest: true }, window => {
        render(window.start, window.end, window.top);
        requestAnimationFrame(() => controller.update({ ack: true }));
      });
      controller.update({ generation: 1, keys });
    }, layoutSource);
    const feed = page.locator(".message-list");
    const row = page.locator("#chat-message-1");
    await revealTimelineEvent(page, row, 10_000, feed);
    await page.waitForTimeout(150);
    assert.equal(await row.count(), 1,
      "the initial all-row mount must not be mistaken for the settled virtual window");
    assert.equal(await intersectsFeed(row, feed), true);
  } finally { await page.close(); }
});
