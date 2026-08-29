import { expect, test } from "./fixtures";

const nestedBase = "/console";
test("nested public base keeps assets and routes nested while APIs stay at the origin root", async ({
  page,
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
  await page.getByLabel("Email").fill("person@example.test");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Your account", level: 1 })).toBeVisible();
  expect((await page.request.get("/reference-records?limit=1")).status()).toBe(200);
  expect((await page.request.get("/realtime/ws")).status()).toBe(404);
  expect((await page.request.get("/events")).status()).toBe(404);
});
