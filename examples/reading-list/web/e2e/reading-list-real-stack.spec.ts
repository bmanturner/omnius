import { randomUUID } from "node:crypto";

import { expect, test } from "@playwright/test";
import type { APIRequestContext, Page } from "@playwright/test";

const externalBaseUrl = process.env.OMNIUS_E2E_BASE_URL;
const mailpitUrl = process.env.OMNIUS_E2E_MAILPIT_URL ?? "http://127.0.0.1:8025";

test.skip(
  externalBaseUrl === undefined,
  "reading-list journey only runs against the external Compose stack",
);

// Authentication fragments must not be retained in failure artifacts.
test.use({ trace: "off", screenshot: "off", video: "off" });

interface MailpitAddress {
  readonly Address?: string;
}

interface MailpitSummary {
  readonly ID?: string;
  readonly To?: readonly MailpitAddress[];
}

interface MailpitList {
  readonly messages?: readonly MailpitSummary[];
}

interface MailpitMessage {
  readonly Text?: string;
  readonly HTML?: string;
}

function observeBrowserFailures(page: Page) {
  let pageErrors = 0;
  let consoleErrors = 0;
  let failedSameOriginRequests = 0;
  const applicationOrigin = new URL(externalBaseUrl!).origin;
  page.on("pageerror", () => { pageErrors += 1; });
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors += 1;
  });
  page.on("requestfailed", (request) => {
    if (new URL(request.url()).origin === applicationOrigin) failedSameOriginRequests += 1;
  });
  return () => {
    expect(pageErrors, "page errors").toBe(0);
    expect(consoleErrors, "console errors").toBe(0);
    expect(failedSameOriginRequests, "failed same-origin requests").toBe(0);
  };
}

async function findVerificationLocation(
  request: APIRequestContext,
  recipient: string,
): Promise<string | undefined> {
  const listing = await request.get(`${mailpitUrl}/api/v1/messages`);
  if (!listing.ok()) return undefined;
  const messages = (await listing.json()) as MailpitList;
  const message = messages.messages?.find((candidate) =>
    candidate.To?.some((address) => address.Address?.toLowerCase() === recipient.toLowerCase()),
  );
  if (message?.ID === undefined) return undefined;

  const response = await request.get(
    `${mailpitUrl}/api/v1/message/${encodeURIComponent(message.ID)}`,
  );
  if (!response.ok()) return undefined;
  const body = (await response.json()) as MailpitMessage;
  const content = `${body.Text ?? ""}\n${body.HTML ?? ""}`;
  const match = content.match(/https?:\/\/[^\s"'<>]+\/verify-email#token=[^\s"'<>]+/u);
  if (match?.[0] === undefined) return undefined;
  const verification = new URL(match[0].replaceAll("&amp;", "&"));
  return `${verification.pathname}${verification.search}${verification.hash}`;
}

test("registration through logout uses the real authenticated reading-list stack", async ({ page, request }) => {
  test.setTimeout(60_000);
  const assertNoBrowserFailures = observeBrowserFailures(page);
  const email = `reading-list-${randomUUID()}@example.test`;
  const password = "Synthetic-e2e-password-2026";

  await page.goto("/register");
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Check your email" })).toBeVisible();

  let verificationLocation: string | undefined;
  await expect.poll(async () => {
    verificationLocation = await findVerificationLocation(request, email);
    return verificationLocation !== undefined;
  }, { timeout: 20_000, message: "verification email arrives in Mailpit" }).toBe(true);
  if (verificationLocation === undefined) throw new Error("Mailpit verification link was unavailable");

  await page.evaluate((location) => { window.location.assign(location); }, verificationLocation);
  await expect(page).toHaveURL(/\/verify-email$/u);
  await expect(page.getByRole("heading", { name: "Your email is verified" })).toBeVisible();
  await expect(page.locator("body")).not.toContainText("token=");
  expect(await page.evaluate(() => ({
    hash: location.hash,
    local: localStorage.length,
    session: sessionStorage.length,
  }))).toEqual({ hash: "", local: 0, session: 0 });

  await page.getByRole("main").getByRole("link", { name: "Sign in" }).click();
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Your list is empty" })).toBeVisible();

  await page.getByLabel("Title").fill("Persistent article");
  await page.getByLabel("Web address").fill("HTTPS://Example.Test/read-next");
  await page.getByRole("button", { name: "Add to list" }).click();
  await expect(page.getByRole("link", { name: /Persistent article/ })).toBeVisible();
  await page.reload();
  await expect(page.getByRole("link", { name: /Persistent article/ })).toBeVisible();
  await expect(page.getByText("https://example.test/read-next")).toBeVisible();

  await page.getByRole("button", { name: "Mark as finished: Persistent article" }).click();
  await expect(page.getByText("Marked as finished.")).toBeVisible();
  await expect(page.getByText("Finished", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Delete Persistent article" }).click();
  await expect(page.getByRole("button", { name: "Keep item" })).toBeFocused();
  await page.getByRole("button", { name: "Delete item" }).click();
  await expect(page.getByRole("heading", { name: "Your list is empty" })).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in to Reading List" })).toBeVisible();
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Sign in to Reading List" })).toBeVisible();
  assertNoBrowserFailures();
});

test("extensionless application deep links are served by the real static fallback @smoke", async ({ request }) => {
  for (const path of [
    "/login",
    "/register",
    "/forgot-password",
    "/verify-email",
    "/reset-password",
  ]) {
    const response = await request.get(path);
    expect(response.status(), path).toBe(200);
    expect(response.headers()["content-type"], path).toContain("text/html");
    expect(await response.text(), path).toContain('<div id="root"></div>');
  }
});
