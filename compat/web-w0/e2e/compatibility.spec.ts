import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("pinned browser renders an accessible React shell", async ({ page }) => {
  await page.goto("/");
  await expect(
    page.getByText("Omnius web compatibility fixture"),
  ).toBeVisible();
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);
});
