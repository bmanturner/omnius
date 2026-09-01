import type { Page } from "@playwright/test";

import {
  expect,
  expectRuntimeCapabilityUnavailable,
  hasRuntimeCapability,
  test,
} from "./fixtures";

const managedFixturePort = Number.parseInt(process.env.OMNIUS_E2E_PORT ?? "4174", 10);
const managedBaseUrl = `http://127.0.0.1:${managedFixturePort}`;

async function login(page: Page): Promise<void> {
  await page.goto(`${managedBaseUrl}/account`);
  await page.getByLabel("Email").fill("person@example.test");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Your account", level: 1 })).toBeVisible();
}

test("logout-all follows the runtime web-auth capability", async ({
  browser,
  runtimeMetadata,
}) => {
  test.skip(
    process.env.OMNIUS_E2E_BASE_URL !== undefined,
    "The disposable identity workflow belongs to the managed local fixture.",
  );
  if (!hasRuntimeCapability(runtimeMetadata, "web-auth")) {
    const context = await browser.newContext();
    try {
      await expectRuntimeCapabilityUnavailable(await context.newPage(), "/account");
    } finally {
      await context.close();
    }
    return;
  }
  const firstContext = await browser.newContext();
  const secondContext = await browser.newContext();
  try {
    const first = await firstContext.newPage();
    const second = await secondContext.newPage();
    await login(first);
    await login(second);

    const denied = await first.evaluate(async () => {
      const response = await fetch("/auth/permissions/privileged", { method: "POST" });
      return {
        body: (await response.json()) as { readonly code?: string },
        contentType: response.headers.get("content-type"),
        status: response.status,
      };
    });
    expect(denied.status).toBe(403);
    expect(denied.contentType).toContain("application/problem+json");
    expect(denied.body.code).toBe("PERMISSION_DENIED");

    const revoked = await first.evaluate(async () => {
      const response = await fetch("/auth/logout-all", { method: "POST" });
      return response.status;
    });
    expect(revoked).toBe(204);

    await expect.poll(async () =>
      second.evaluate(async () => (await fetch("/auth/session")).status),
    ).toBe(401);
    await second.reload();
    await expect(second.getByRole("heading", { name: "Sign in", level: 1 })).toBeVisible();
  } finally {
    await firstContext.close();
    await secondContext.close();
  }
});

test("the built shell fails visibly when live runtime metadata has a different contract hash", async ({
  page,
}) => {
  await page.route("**/api/_meta", async (route) => {
    const response = await route.fetch();
    const body = await response.json() as Record<string, unknown>;
    await route.fulfill({
      response,
      headers: {
        ...response.headers(),
        "x-omnius-contract-hash": "0".repeat(64),
      },
      json: { ...body, contract_hash: `sha256:${"0".repeat(64)}` },
    });
  });

  await page.goto("/");
  const alert = page.getByRole("alert");
  await expect(alert).toBeVisible();
  await expect(alert).toContainText(
    "The service runtime contract does not match the contract used to generate this SDK.",
  );
});
