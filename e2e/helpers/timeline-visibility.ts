import { expect, type Locator, type Page } from "@playwright/test";

export async function sampleAndAdvanceTimeline(feed: Locator): Promise<string[]> {
  return feed.evaluate(element => {
    const mounted = Array.from(element.querySelectorAll<HTMLElement>(".chat-message"));
    const sample = mounted.map(row => row.textContent ?? "");
    const bounds = element.getBoundingClientRect();
    const viewportBottom = bounds.top + element.clientTop + element.clientHeight;
    // Read rows and geometry in one DOM turn. An overscan tail can extend far
    // past the viewport while its estimated heights are still being corrected.
    const visibleTail = mounted.find(row => row.getBoundingClientRect().bottom >= viewportBottom);
    const next = visibleTail ? visibleTail.getBoundingClientRect().bottom - bounds.top
      - element.clientTop + element.scrollTop - element.clientHeight * 0.5 : 0;
    element.scrollTop = Math.max(element.scrollTop + Math.max(1, element.clientHeight * 0.65), next);
    return sample;
  });
}

export async function revealTimelineEvent(
  page: Page,
  event: Locator,
  timeout = 30_000,
  feed: Locator = page.locator(".message-list"),
): Promise<void> {
  let restart = true;
  await expect.poll(async () => {
    if (await event.count()) {
      let target;
      try {
        target = await event.first().elementHandle({ timeout: 1_000 });
        if (!target) return false;
        return await target.evaluate(async element => {
          // The initial mount can precede the virtualizer's first tail window.
          // Keep the actual target in view through the pending layout frames.
          element.scrollIntoView({ block: "nearest", inline: "nearest", behavior: "instant" });
          for (let frame = 0; frame < 2; frame++) {
            await new Promise<void>(resolve => requestAnimationFrame(() => resolve()));
          }
          const viewport = element.closest(".message-list");
          if (!element.isConnected || !viewport) return false;
          const row = element.getBoundingClientRect();
          const bounds = viewport.getBoundingClientRect();
          const top = bounds.top + viewport.clientTop;
          const bottom = top + viewport.clientHeight;
          return row.height > 0 && viewport.clientHeight > 0
            && row.bottom > top && row.top < bottom;
        });
      } catch (error) {
        if (page.isClosed()) throw error;
        return false;
      } finally {
        await target?.dispose().catch(() => {});
      }
    }
    // Unmounted virtual rows cannot scrollIntoView. Traverse the actual feed,
    // allowing each layout update to mount its window before the next probe.
    restart = await feed.evaluate((element, fromStart) => {
      if (fromStart) {
        element.scrollTop = 0;
        return false;
      }
      const before = element.scrollTop;
      element.scrollTop += Math.max(1, element.clientHeight * 0.75);
      return element.scrollTop === before;
    }, restart);
    return false;
  }, {
    timeout,
    intervals: [250],
    message: "timeline action target must remain visible through virtual layout updates",
  }).toBe(true);
}
