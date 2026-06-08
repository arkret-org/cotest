import { expect, type Locator } from "@playwright/test";

/**
 * 选择一个 dioxus-components(dxc)Select 的选项。
 *
 * 背景:yougen 前端从原生 `<select>` 迁移到 dxc `Select`(dioxus-primitives)后,
 * 下拉渲染为自定义弹层 —— `button[aria-haspopup="listbox"]` 触发 +
 * `div[role="listbox"]` 容器 + 一组 `div[role="option"]`,不再是原生
 * `<select>`/`<option>`。因此 Playwright 的 `locator.selectOption()` 会抛
 * `Element is not a <select> element`,所有沿用它的 e2e 都会崩。
 *
 * yougen 的 `SelectOption` 把底层 value 暴露为 `data-value`(见
 * `yougen/src/ui/select/component.rs`),本 helper 据此按 value 定位并点击,
 * 调用语义与原 `selectOption(value)` 等价(传入的字符串不变)。
 *
 * @param scope 指向 Select 外层容器的 Locator(通常 `page.getByTestId("xxx-select")`)
 * @param value 选项的底层 value(与原 `selectOption` 的第一个参数完全一致)
 */
export async function selectDxcOption(scope: Locator, value: string): Promise<void> {
  const trigger = scope.locator('button[aria-haspopup="listbox"]').first();
  await expect(trigger).toBeVisible({ timeout: 30_000 });
  if ((await trigger.getAttribute("aria-expanded")) !== "true") {
    await trigger.click();
  }
  const option = scope.locator(`[role="option"][data-value="${value}"]`);
  await option.click();
  // 单选选中后 dxc 会收起弹层;等待 aria-expanded 复位,避免后续操作命中残留 overlay。
  await expect(trigger).toHaveAttribute("aria-expanded", "false", { timeout: 30_000 });
}
