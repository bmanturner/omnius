import { expect, test } from "./fixtures";

const nestedBase = "/console";
const sseSubscriptionId = "01890f2a-0000-7000-8000-000000000041";

test("nested public base keeps assets and routes nested while API, WS, and SSE stay at the origin root", async ({
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
  const websocket = page.waitForEvent("websocket");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Workspace", level: 1 })).toBeVisible();
  expect((await page.request.get("/reference-records?limit=1")).status()).toBe(200);
  expect(new URL((await websocket).url()).pathname).toBe("/realtime/ws");

  const ssePath = `/events?subscription_id=${sseSubscriptionId}&topic=reference-records`;
  const sseResponse = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.pathname === "/events"
      && url.searchParams.get("subscription_id") === sseSubscriptionId;
  });
  await page.evaluate(async (path) => {
    await new Promise<void>((resolve, reject) => {
      const source = new EventSource(path);
      const timeout = globalThis.setTimeout(() => {
        source.close();
        reject(new Error("nested-base SSE stream did not open"));
      }, 5_000);
      source.onopen = () => {
        globalThis.clearTimeout(timeout);
        source.close();
        resolve();
      };
      source.onerror = () => {
        globalThis.clearTimeout(timeout);
        source.close();
        reject(new Error("nested-base SSE stream failed"));
      };
    });
  }, ssePath);
  expect((await sseResponse).headers()["content-type"]).toContain("text/event-stream");
});
