import type { Locator } from "@playwright/test";

/** Measure rendered text fragments, including wrappers with display: contents. */
export async function readTextLineLayout(target: Locator) {
  return target.evaluate(element => {
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    const fragments: Array<{ top: number; bottom: number; height: number }> = [];
    while (walker.nextNode()) {
      const text = walker.currentNode;
      if (!text.textContent?.trim()) continue;
      const range = document.createRange();
      range.selectNodeContents(text);
      for (const rect of Array.from(range.getClientRects())) {
        if (rect.width > 0 && rect.height > 0) {
          fragments.push({ top: rect.top, bottom: rect.bottom, height: rect.height });
        }
      }
    }
    fragments.sort((a, b) => a.top - b.top);
    const lines: Array<{ top: number; bottom: number; height: number }> = [];
    for (const fragment of fragments) {
      const line = lines.find(line => Math.min(line.bottom, fragment.bottom)
        - Math.max(line.top, fragment.top) > Math.min(line.height, fragment.height) / 2);
      if (line) {
        line.top = Math.min(line.top, fragment.top);
        line.bottom = Math.max(line.bottom, fragment.bottom);
      } else lines.push({ ...fragment });
    }
    return { fragment_count: fragments.length, line_count: lines.length };
  });
}
