import { expect, hasRuntimeCapability, test } from "./fixtures";

const nestedBase = "/console";
test("nested public base keeps assets and routes nested while APIs stay at the origin root", async ({
  page,
  runtimeMetadata,
}) => {
  test.skip(
    process.env.OMNIUS_WEB_BASE_PATH !== nestedBase,
    "Run through the dedicated nested-base browser command.",
  );

  const shell = await page.goto(`${nestedBase}/records?limit=25`);
  expect(shell?.status()).toBe(200);
  await expect(page.getByRole("heading", { name: "Reference records", level: 1 })).toBeVisible();
  const scriptSource = await page.locator("script[src]").first().getAttribute("src");
  expect(scriptSource).toMatch(/^\/console\/assets\/.+-[A-Za-z0-9_-]+\.js$/u);
  expect((await page.request.get(scriptSource ?? "/missing.js")).status()).toBe(200);

  await page.goto(`${nestedBase}/account`);
  const webAuthAvailable = hasRuntimeCapability(runtimeMetadata, "web-auth");
  if (webAuthAvailable) {
    await page.getByLabel("Email").fill("person@example.test");
    await page.getByLabel("Password").fill("correct horse battery staple");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("heading", { name: "Your account", level: 1 })).toBeVisible();
  } else {
    await expect(page.getByRole("heading", { name: "Feature unavailable" })).toBeVisible();
  }
  const referenceRecords = await page.request.get("/reference-records?limit=1");
  expect(referenceRecords.status()).toBe(webAuthAvailable ? 200 : 401);
  if (!webAuthAvailable) {
    expect(referenceRecords.headers()["content-type"]).toContain("application/problem+json");
  }
  for (const path of ["/realtime/ws", "/realtime/events"]) {
    const response = await page.request.get(path);
    expect(response.headers()["content-type"] ?? "").not.toContain("text/html");
  }
});
