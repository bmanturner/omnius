import {
  authenticateBrowserSession,
  createBearerToken,
  createReferenceRecord,
  expect,
  operationIds,
  test,
} from "./fixtures";


test("production CSP and clickjacking protections are enforced by Axum @smoke", async ({ page }) => {
  const response = await page.goto("/");
  expect(response).not.toBeNull();
  const headers = response?.headers() ?? {};
  const csp = headers["content-security-policy"] ?? "";
  for (const directive of [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ]) {
    expect(csp).toContain(directive);
  }
  expect(csp).not.toContain("'unsafe-eval'");
  expect(csp).not.toContain("'unsafe-inline'");
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["referrer-policy"]).toBe("no-referrer");
  expect(headers["permissions-policy"]).toContain("camera=()");
});

test("authenticated browser use never places credentials in JavaScript-visible storage", async ({
  page,
}) => {
  const token = createBearerToken();
  await page.setExtraHTTPHeaders({ authorization: `Bearer ${token}` });
  await page.goto("/records?limit=25");
  const evidence = await page.evaluate(async () => {
    const identity = await fetch("/whoami");
    return {
      identityStatus: identity.status,
      localStorageKeys: Object.keys(localStorage),
      sessionStorageKeys: Object.keys(sessionStorage),
      visibleCookie: document.cookie,
    };
  });
  expect(evidence.identityStatus).toBe(200);
  expect(evidence.localStorageKeys).toEqual([]);
  expect(evidence.sessionStorageKeys).toEqual([]);
  expect(evidence.visibleCookie).toBe("");
  expect(await page.context().cookies()).toEqual([]);
  const html = await page.content();
  expect(html).not.toContain(token);
});

test("cross-origin mutations are rejected without changing records", async ({ request }) => {
  await authenticateBrowserSession(request);
  const before = await request.get("/reference-records?limit=100");
  expect(before.status()).toBe(200);
  const beforeBody = (await before.json()) as { readonly items: readonly unknown[] };

  const rejected = await request.post("/reference-records", {
    data: { name: "Cross-origin record must not exist" },
    headers: {
      "content-type": "application/json",
      "idempotency-key": "cross-origin-csrf-negative",
      origin: "https://attacker.invalid",
    },
  });
  expect(rejected.status()).toBe(403);
  expect(rejected.headers()["access-control-allow-origin"]).toBeUndefined();

  const after = await request.get("/reference-records?limit=100");
  expect(after.status()).toBe(200);
  const afterBody = (await after.json()) as { readonly items: readonly unknown[] };
  expect(afterBody.items).toHaveLength(beforeBody.items.length);
});

test("unknown redirect inputs cannot become an external navigation sink", async ({
  openApi,
  page,
}) => {
  const requestedOrigins = new Set<string>();
  page.on("request", (request) => requestedOrigins.add(new URL(request.url()).origin));
  await page.goto("/?returnTo=https%3A%2F%2Fattacker.invalid%2Fcapture");
  await expect(page.getByRole("heading", { name: "Service overview", level: 1 })).toBeVisible();
  await page.goto("/records?limit=25&redirect=https%3A%2F%2Fattacker.invalid%2Fcapture");
  await expect(page.getByRole("heading", { name: "Reference records", level: 1 })).toBeVisible();
  expect(new URL(page.url()).origin).not.toBe("https://attacker.invalid");
  expect([...requestedOrigins]).not.toContain("https://attacker.invalid");
  expect(operationIds(openApi).join(" ")).not.toMatch(/redirect|callback/iu);
});

test("fragment-carried account secrets are removed without touching browser storage", async ({ page }) => {
  const resetSecret = "reset-secret-visible-only-in-memory";
  await page.goto(`/reset-password#token=${resetSecret}`);
  await expect(page.getByRole("heading", { name: "Choose a new password", level: 1 })).toBeVisible();
  await expect(page).toHaveURL(/\/reset-password$/u);
  expect(await page.locator("body").textContent()).not.toContain(resetSecret);

  const invitationSecret = "invitation-secret-visible-only-in-memory";
  await page.goto(`/register#invitation=${invitationSecret}`);
  await expect(page.getByRole("heading", { name: "Create your account", level: 1 })).toBeVisible();
  await expect(page).toHaveURL(/\/register$/u);
  const storage = await page.evaluate(() => ({
    local: Object.keys(localStorage),
    session: Object.keys(sessionStorage),
  }));
  expect(storage).toEqual({ local: [], session: [] });
  expect(await page.locator("body").textContent()).not.toContain(invitationSecret);
});

test("login rejects an external return target after successful authentication", async ({ page }) => {
  await page.goto("/login?returnTo=https%3A%2F%2Fattacker.invalid%2Fcapture");
  await page.getByLabel("Email").fill("person@example.test");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Your account", level: 1 })).toBeVisible();
  expect(new URL(page.url()).origin).not.toBe("https://attacker.invalid");
});

test("server data containing active-markup syntax stays inert React text", async ({ page }) => {
  await authenticateBrowserSession(page.request);
  const payload = "<img src=x onerror=window.__omniusXss=1>";
  const created = await createReferenceRecord(page.request, payload, "browser-xss-boundary");
  expect(created.status()).toBe(201);

  await page.goto("/records?limit=100");
  await expect(page.locator(".record-name").getByText(payload, { exact: true })).toBeVisible();
  expect(await page.locator("img[src='x']").count()).toBe(0);
  const executionMarker = await page.evaluate(
    () => (globalThis as typeof globalThis & { __omniusXss?: unknown }).__omniusXss,
  );
  expect(executionMarker).toBeUndefined();
});

test("production assets expose neither source maps nor fixture secrets", async ({ page }) => {
  await page.goto("/");
  const scriptSources = await page.locator("script[src]").evaluateAll((scripts) =>
    scripts.flatMap((script) => {
      const source = script.getAttribute("src");
      return source === null ? [] : [source];
    }),
  );
  expect(scriptSources.length).toBeGreaterThan(0);
  for (const source of scriptSources) {
    const script = await page.request.get(source);
    expect(script.status()).toBe(200);
    const body = await script.text();
    expect(body).not.toContain("BEGIN PRIVATE KEY");
    expect(body).not.toContain("0123456789abcdef0123456789abcdef");
    expect(body).not.toMatch(/VITE_[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|KEY)/u);

    const sourceMap = await page.request.get(`${source}.map`);
    expect(sourceMap.status()).toBe(404);
    expect(sourceMap.headers()["content-type"] ?? "").not.toContain("application/json");
  }
});
