import { expect, test } from "@playwright/test";

test.skip(
  process.env.OMNIUS_E2E_PROFILE_BIN === undefined,
  "generated-profile smoke only runs in the generated matrix",
);

test("generated web profile serves its built SPA without swallowing APIs @smoke", async ({ page }) => {
  const shell = await page.goto("/");
  expect(shell?.status()).toBe(200);
  expect(shell?.headers()["content-security-policy"]).toContain("default-src 'self'");
  await expect(page.locator("#root")).toBeAttached();

  const assetPath = await page.locator('script[type="module"]').getAttribute("src");
  expect(assetPath).toMatch(/^\/assets\/.+\.js$/u);
  const asset = await page.request.get(assetPath ?? "/missing");
  expect(asset.status()).toBe(200);
  expect(asset.headers()["content-type"]).toContain("text/javascript");
  expect(asset.headers()["cache-control"]).toContain("immutable");

  const deepLink = await page.request.get("/generated-profile/deep-link");
  expect(deepLink.status()).toBe(200);
  expect(deepLink.headers()["content-type"]).toContain("text/html");

  const reservedApi = await page.request.get("/api/unknown");
  expect(reservedApi.status()).toBe(404);
  expect(reservedApi.headers()["content-type"] ?? "").not.toContain("text/html");

  const ready = await page.request.get("/ready");
  expect(ready.status()).toBe(200);
  await expect(ready.json()).resolves.toEqual({ status: "ready" });
});
