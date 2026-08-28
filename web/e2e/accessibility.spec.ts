import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures";

async function expectNoAxeViolations(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(
    results.violations,
    results.violations
      .map((violation) => `${violation.id}: ${violation.nodes.length} affected node(s)`) 
      .join("\n"),
  ).toEqual([]);
}

test("service overview passes the representative axe gate @smoke", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Service overview", level: 1 })).toBeVisible();
  await expectNoAxeViolations(page);
});

test("records, error, and not-found states pass axe", async ({ page }) => {
  const representativeRoutes = [
    {
      path: "/records?limit=25",
      ready: page.getByRole("heading", { name: "Reference records", level: 1 }),
    },
    {
      path: "/records?limit=25&cursor=not-a-valid-cursor",
      ready: page.getByRole("alert"),
    },
    {
      path: "/not-a-real-browser-route",
      ready: page.getByRole("heading", { name: "Page not found", level: 1 }),
    },
  ] as const;

  for (const route of representativeRoutes) {
    await page.goto(route.path);
    await expect(route.ready).toBeVisible();
    await expectNoAxeViolations(page);
  }
});

test("skip navigation and route focus management work from the keyboard @smoke", async (
  { page },
  testInfo,
) => {
  await page.goto("/");
  await page.bringToFront();
  await page.keyboard.press(testInfo.project.name === "webkit" ? "Alt+Tab" : "Tab");
  const skipLink = page.getByRole("link", { name: "Skip to main content" });
  await expect(skipLink).toBeFocused();
  await expect(skipLink).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();

  await page.getByRole("link", { name: "Reference records" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Reference records", level: 1 })).toBeVisible();
  await expect(page.locator("#main-content")).toBeFocused();
  await expect(page).toHaveTitle("Reference records · Omnius");
  await expect(page.getByLabel("Records per page")).toBeVisible();
});

test("asynchronous and error states expose explicit semantics", async ({ page }) => {
  await page.goto("/records?limit=25&cursor=not-a-valid-cursor");
  const alert = page.getByRole("alert");
  await expect(alert).toBeVisible();
  await expect(alert.getByRole("heading", { level: 2 })).toBeVisible();
  await expect(alert).toContainText("Request ID:");
  await expect(page.locator("main")).toHaveAttribute("tabindex", "-1");
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
});
