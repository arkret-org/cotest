import { expect, type Locator, type Page } from "@playwright/test";

export async function sampleAndAdvanceTimeline(feed: Locator): Promise<string[]> {
  return feed.evaluate(element => {
    const mounted = Array.from(element.querySelectorAll<HTMLElement>("[data-virtual-index]"));
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
): Promise<void> {
  const feed = page.getByTestId("message-list");
  let restart = true;
  await expect.poll(async () => {
    if (await event.count()) return true;
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
    message: "timeline action target must be mounted through the visible feed",
  }).toBe(true);
}
