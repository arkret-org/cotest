import { expect, type Locator, type Page } from "@playwright/test";

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
