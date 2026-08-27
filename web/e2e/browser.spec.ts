import {
  REFERENCE_SUBJECT_ID,
  REFERENCE_TENANT_ID,
  capabilityContract,
  createBearerToken,
  createReferenceRecord,
  expect,
  operationIds,
  test,
} from "./fixtures";

test("production shell and non-reserved deep links come from Axum @smoke", async ({ page }) => {
  const shell = await page.goto("/");
  expect(shell).not.toBeNull();
  expect(shell?.status()).toBe(200);
  expect(shell?.headers()["content-type"]).toContain("text/html");
  expect(shell?.headers()["cache-control"]).toBe("no-cache");
  await expect(page.getByRole("heading", { name: "Service overview", level: 1 })).toBeVisible();
  await expect(page.getByText("ready", { exact: true }).first()).toBeVisible();

  const deepLink = await page.goto("/records?limit=25");
  expect(deepLink?.status()).toBe(200);
  expect(deepLink?.headers()["content-type"]).toContain("text/html");
  await expect(page.getByRole("heading", { name: "Reference records", level: 1 })).toBeVisible();
  await expect(page.getByLabel("Records per page")).toHaveValue("25");

  const reservedApi = await page.request.get("/reference-records?limit=25");
  expect(reservedApi.status()).toBe(200);
  expect(reservedApi.headers()["content-type"]).toContain("application/json");
});

test("unauthenticated and authenticated record deep links use the real identity boundary", async ({
  page,
}) => {
  await page.goto("/records?limit=25");
  await expect(page.getByRole("heading", { name: "Reference records", level: 1 })).toBeVisible();
  const denied = await page.evaluate(async () => {
    const response = await fetch("/whoami");
    return {
      body: (await response.json()) as unknown,
      contentType: response.headers.get("content-type"),
      status: response.status,
    };
  });
  expect(denied.status).toBe(401);
  expect(denied.contentType).toContain("application/problem+json");
  expect(denied.body).toMatchObject({ code: "AUTHENTICATION_REQUIRED" });

  await page.setExtraHTTPHeaders({ authorization: `Bearer ${createBearerToken()}` });
  await page.goto("/records?limit=25");
  const authenticated = await page.evaluate(async () => {
    const response = await fetch("/whoami");
    return {
      body: (await response.json()) as unknown,
      status: response.status,
    };
  });
  expect(authenticated.status).toBe(200);
  expect(authenticated.body).toMatchObject({
    subject_id: REFERENCE_SUBJECT_ID,
    tenant_id: REFERENCE_TENANT_ID,
    auth_method: "jwt",
  });
});

test("expired bearer credentials fail closed at the actual identity endpoint", async ({ request }) => {
  const response = await request.get("/whoami", {
    headers: {
      authorization: `Bearer ${createBearerToken({ expiresAt: Math.floor(Date.now() / 1000) - 120 })}`,
    },
  });
  expect(response.status()).toBe(401);
  expect(response.headers()["content-type"]).toContain("application/problem+json");
  expect(await response.json()).toMatchObject({ code: "AUTHENTICATION_REQUIRED" });
});

test("page-size search and cursor pagination stay URL-owned", async ({ page, request }) => {
  for (let index = 0; index < 11; index += 1) {
    const response = await createReferenceRecord(
      request,
      `Browser pagination record ${String(index).padStart(2, "0")}`,
      `browser-pagination-${String(index).padStart(2, "0")}`,
    );
    expect(response.status()).toBe(201);
  }

  await page.goto("/records?limit=10");
  await expect(page.getByText("10 shown", { exact: true })).toBeVisible();
  const firstPageNames = await page.locator(".record-name").allTextContents();
  await page.getByRole("link", { name: "Next page" }).click();
  await expect(page).toHaveURL(/\/records\?cursor=.+&limit=10|\/records\?limit=10&cursor=.+/u);
  await expect(page.getByRole("link", { name: "Return to first page" })).toBeVisible();
  const nextPageNames = await page.locator(".record-name").allTextContents();
  expect(nextPageNames).not.toEqual(firstPageNames);

  await page.getByLabel("Records per page").selectOption("50");
  await expect(page).toHaveURL(/\/records\?limit=50/u);
  await expect(page.getByLabel("Records per page")).toHaveValue("50");
});

test("RFC 9457 errors render a safe request ID", async ({ page }) => {
  await page.goto("/records?limit=25&cursor=not-a-valid-cursor");
  const alert = page.getByRole("alert");
  await expect(alert).toBeVisible();
  await expect(alert).toContainText("Request ID:");
  await expect(alert.locator("code.request-id")).toHaveText(/^[A-Za-z0-9_-]{8,128}$/u);
});

test("the assembled capability ceiling is explicit instead of faking product endpoints @smoke", async ({
  openApi,
  request,
  runtimeMetadata,
}) => {
  expect(runtimeMetadata.profile).toBe(capabilityContract.profile);
  expect(runtimeMetadata.contract_hash).toBe(capabilityContract.contract_hash);
  expect(runtimeMetadata.transports).toEqual(capabilityContract.transports);
  expect(runtimeMetadata.capabilities).toEqual(
    capabilityContract.capabilities.map((capability) => capability.id),
  );

  const unavailable = capabilityContract.capabilities
    .filter((capability) => !capability.runtime_available)
    .map((capability) => capability.id);
  expect(unavailable).toEqual(["web-realtime", "web-uploads"]);

  const actualOperationIds = operationIds(openApi);
  expect(actualOperationIds).toContain("getCurrentPrincipal");
  expect(actualOperationIds.join(" ")).not.toMatch(
    /login|logout|session|tenant|permission|upload|websocket|server.sent|realtime/iu,
  );

  for (const transport of [capabilityContract.transports.sse, capabilityContract.transports.websocket]) {
    const response = await request.get(transport);
    expect(response.status()).toBe(404);
    expect(response.headers()["content-type"] ?? "").not.toContain("text/html");
  }
});

test("SPA fallback and asset caching follow production delivery policy @smoke", async ({ page }) => {
  const shell = await page.goto("/records?limit=25");
  expect(shell?.headers()["cache-control"]).toBe("no-cache");
  const scriptSource = await page.locator("script[src]").first().getAttribute("src");
  expect(scriptSource).toMatch(/^\/assets\/.+-[A-Za-z0-9_-]+\.js$/u);
  const asset = await page.request.get(scriptSource ?? "/missing-entry.js");
  expect(asset.status()).toBe(200);
  expect(asset.headers()["cache-control"]).toBe("public, max-age=31536000, immutable");
  expect(asset.headers().etag).toBeDefined();

  const unknown = await page.goto("/browser-route-that-does-not-exist");
  expect(unknown?.status()).toBe(200);
  await expect(page.getByRole("heading", { name: "Page not found", level: 1 })).toBeVisible();
});

test("the built shell and actual runtime prove contract compatibility", async ({
  page,
  request,
  runtimeMetadata,
}) => {
  await page.goto("/");
  await expect(page.locator(".build-hash")).toHaveText(runtimeMetadata.contract_hash);
  await expect(page.getByRole("alert", { name: "Contract mismatch" })).toHaveCount(0);

  const metadataResponse = await request.get("/api/_meta");
  expect(metadataResponse.headers()["x-omnius-contract-hash"]).toBeUndefined();
  expect(runtimeMetadata.contract_hash).toBe(capabilityContract.contract_hash);
});
