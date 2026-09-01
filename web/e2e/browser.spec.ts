import {
  authenticateBrowserSession,
  REFERENCE_SUBJECT_ID,
  REFERENCE_TENANT_ID,
  capabilityContract,
  expectRuntimeCapabilityUnavailable,
  hasRuntimeCapability,
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
  expect(reservedApi.status()).toBe(401);
  expect(reservedApi.headers()["content-type"]).toContain("application/problem+json");
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

test("password login follows the runtime web-auth capability", async ({
  page,
  runtimeMetadata,
}) => {
  if (!hasRuntimeCapability(runtimeMetadata, "web-auth")) {
    await expectRuntimeCapabilityUnavailable(page, "/account/security");
    return;
  }

  await page.goto("/account/security");
  await expect(page.getByRole("heading", { name: "Sign in", level: 1 })).toBeVisible();
  expect(new URL(page.url()).searchParams.get("returnTo")).toBe("/account/security");
  await page.getByLabel("Email").fill("person@example.test");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page.getByRole("heading", { name: "Change password", level: 1 })).toBeVisible();
  await page.getByRole("link", { name: "Account", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Your account", level: 1 })).toBeVisible();
  await expect(page.getByRole("link", { name: "Security", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Sessions", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "API keys", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Connected apps", exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in", level: 1 })).toBeVisible();
});

test("public account routes follow the runtime web-auth capability", async ({
  page,
  runtimeMetadata,
}) => {
  if (!hasRuntimeCapability(runtimeMetadata, "web-auth")) {
    await expectRuntimeCapabilityUnavailable(page, "/login");
    return;
  }

  const routes = [
    { path: "/login", heading: "Sign in" },
    { path: "/register", heading: "Create your account" },
    { path: "/verify-email", heading: "Request a new verification link" },
    { path: "/forgot-password", heading: "Reset your password" },
    { path: "/reset-password", heading: "Reset link unavailable" },
  ] as const;
  for (const route of routes) {
    await page.goto(route.path);
    await expect(page.getByRole("heading", { name: route.heading, level: 1 })).toBeVisible();
  }

  await page.goto("/authorize?request=opaque-fixture-request");
  await expect(page.getByRole("heading", { name: "Sign in", level: 1 })).toBeVisible();
  expect(new URL(page.url()).searchParams.get("returnTo")).toBe(
    "/authorize?request=opaque-fixture-request",
  );
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

test("page-size search and cursor pagination stay URL-owned", async ({ page }) => {
  await authenticateBrowserSession(page.request);
  for (let index = 0; index < 11; index += 1) {
    const response = await createReferenceRecord(
      page.request,
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

test("real filter, server-field form errors, and optimistic conflict recovery stay assembled", async ({
  page,
}) => {
  await authenticateBrowserSession(page.request);
  const suffix = String(Date.now());
  const filterName = `Browser workflow ${suffix}`;
  const recordName = `${filterName} original`;
  const retainedName = `${filterName} retained`;

  await page.goto("/records?limit=25");
  await page.getByLabel("Filter by name").fill(filterName);
  await page.getByRole("button", { name: "Apply filter" }).click();
  await expect
    .poll(() => new URL(page.url()).searchParams.get("name"))
    .toBe(filterName);

  await page.locator("#create-reference-record-name").fill("   ");
  await page.getByRole("button", { name: "Create record" }).click();
  const validationAlert = page.getByRole("alert");
  await expect(validationAlert).toContainText("request body validation failed");
  await expect(page.locator("#create-reference-record-name")).toHaveAttribute("aria-invalid", "true");
  await expect(page.locator("#create-reference-record-name--server-error")).toHaveText(
    "Enter a name between 1 and 100 characters.",
  );

  await page.locator("#create-reference-record-name").fill(recordName);
  await page.getByRole("button", { name: "Create record" }).click();
  await expect(page.locator(".record-name").getByText(recordName, { exact: true })).toBeVisible();

  await page.getByRole("button", { name: `Edit ${recordName}` }).click();
  await page.locator("#edit-reference-record-name").fill(retainedName);
  const recordId = await page
    .locator("tr")
    .filter({ hasText: recordName })
    .locator(".record-id")
    .textContent();
  if (recordId === null) {
    throw new Error("created record row omitted its identifier");
  }
  const competingUpdate = await page.request.put(`/reference-records/${recordId}`, {
    data: { name: `${filterName} server` },
    headers: {
      "content-type": "application/json",
      "if-match": "\"v1\"",
      origin: new URL(page.url()).origin,
    },
  });
  expect(competingUpdate.status()).toBe(200);

  await page.getByRole("button", { name: "Save changes" }).click();
  const conflictAlert = page.getByRole("alert");
  await expect(conflictAlert).toContainText("HTTP 412");
  await conflictAlert.getByRole("button", { name: "Keep my name and retry" }).click();
  await expect(page.locator(".record-name").getByText(retainedName, { exact: true })).toBeVisible();

  const filtered = await page.request.get(
    `/reference-records?limit=25&name=${encodeURIComponent(filterName.toUpperCase())}`,
  );
  expect(filtered.status()).toBe(200);
  const filteredBody = (await filtered.json()) as {
    readonly items: readonly { readonly name: string }[];
  };
  expect(filteredBody.items.some((record) => record.name === retainedName)).toBe(true);
  expect(
    filteredBody.items.every((record) =>
      record.name.toLowerCase().includes(filterName.toLowerCase()),
    ),
  ).toBe(true);
});

test("RFC 9457 errors render a safe request ID", async ({ page }) => {
  await authenticateBrowserSession(page.request);
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
    capabilityContract.capabilities
      .filter((capability) => capability.compiled && capability.runtime_available)
      .map((capability) => capability.id),
  );

  const unavailable = capabilityContract.capabilities
    .filter((capability) => !capability.runtime_available)
    .map((capability) => capability.id);
  if (runtimeMetadata.profile === "web") {
    expect(runtimeMetadata.capabilities).not.toContain("web-realtime");
  } else if (runtimeMetadata.profile === "realtime-web") {
    expect(runtimeMetadata.capabilities).toContain("web-realtime");
    expect(runtimeMetadata.transports).toMatchObject({
      sse: "/realtime/events",
      websocket: "/realtime/ws",
    });
  } else if (runtimeMetadata.profile === "saas-web") {
    expect(
      runtimeMetadata.capabilities.includes("web-uploads") ||
        unavailable.includes("web-uploads"),
    ).toBe(true);
  } else {
    expect(unavailable).toContain("web-auth");
  }

  const actualOperationIds = operationIds(openApi);
  expect(actualOperationIds).toContain("getCurrentPrincipal");
  expect(actualOperationIds).toContain("loginBrowserSession");
  expect(actualOperationIds).toContain("oauth.discovery.authorization-server");
  expect(actualOperationIds).toContain("oidc.discovery");
  expect(actualOperationIds).toContain("oauth.token");
  expect(actualOperationIds).not.toContain("initiateBrowserUpload");

  for (const path of ["/realtime/events", "/realtime/ws", "/uploads", "/webhooks/inbound/provider"]) {
    const response = await request.get(path);
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
