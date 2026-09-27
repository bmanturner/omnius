import { expect, test } from "@playwright/test";

const profileBinary = process.env.OMNIUS_E2E_PROFILE_BIN;
const runtimeProfile = process.env.OMNIUS_E2E_PROFILE;

test.skip(
  profileBinary === undefined,
  "generated-profile smoke only runs in the generated matrix",
);

test("generated web profile serves its built SPA without swallowing reserved backend paths @smoke", async ({ page }) => {
  const shell = await page.goto("/");
  expect(shell?.status()).toBe(200);
  expect(shell?.headers()["content-security-policy"]).toContain("default-src 'self'");
  await expect(page.locator("#root")).toBeAttached();
  await expect(page.getByText("Verifying service capabilities")).toHaveCount(0);

  const assetPath = await page.locator('script[type="module"]').getAttribute("src");
  expect(assetPath).toMatch(/^\/assets\/.+\.js$/u);
  const asset = await page.request.get(assetPath ?? "/missing");
  expect(asset.status()).toBe(200);
  expect(asset.headers()["content-type"]).toContain("text/javascript");
  expect(asset.headers()["cache-control"]).toContain("immutable");

  const deepLink = await page.request.get("/generated-profile/deep-link");
  expect(deepLink.status()).toBe(200);
  expect(deepLink.headers()["content-type"]).toContain("text/html");

  for (const path of [
    "/api/unknown",
    "/realtime/events",
    "/realtime/ws",
    "/uploads/unknown",
  ]) {
    const response = await page.request.get(path);
    expect(response.headers()["content-type"] ?? "").not.toContain("text/html");
  }

  const ready = await page.request.get("/ready");
  expect(ready.status()).toBe(200);
  await expect(ready.json()).resolves.toEqual({ status: "ready" });
});

test("runtime profile metadata distinguishes web composition families @smoke", async ({ request }) => {
  test.skip(runtimeProfile === undefined, "profile identity is supplied by the generated matrix");
  const response = await request.get("/api/_meta");
  expect(response.status()).toBe(200);
  const metadata = (await response.json()) as {
    readonly profile: string;
    readonly capabilities: readonly string[];
    readonly transports: {
      readonly api: string;
      readonly sse?: string;
      readonly websocket?: string;
    };
  };
  expect(metadata.profile).toBe(runtimeProfile);
  expect(metadata.transports.api).toBe("/api");

  if (runtimeProfile === "web") {
    expect(metadata.capabilities).toContain("web-auth");
    expect(metadata.capabilities).not.toContain("web-realtime");
    expect(metadata.transports.sse).toBeUndefined();
    expect(metadata.transports.websocket).toBeUndefined();
  } else if (runtimeProfile === "realtime-web") {
    expect(metadata.capabilities).toEqual(expect.arrayContaining(["web-auth", "web-realtime"]));
    expect(metadata.transports.sse).toBe("/realtime/events");
    expect(metadata.transports.websocket).toBe("/realtime/ws");
  } else if (runtimeProfile === "saas-web") {
    expect(metadata.capabilities).toEqual(expect.arrayContaining(["web-auth", "web-tenancy"]));
    if (process.env.OMNIUS_E2E_UPLOADS_ASSEMBLED === "true") {
      expect(metadata.capabilities).toContain("web-uploads");
    } else {
      expect(metadata.capabilities).not.toContain("web-uploads");
    }
  }
});
