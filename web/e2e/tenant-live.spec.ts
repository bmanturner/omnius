import { expect, test } from "./fixtures";

const primaryTenantId = "01890f2a-0000-7000-8000-000000000002";
const secondaryTenantId = "01890f2a-0000-7000-8000-000000000003";

const cleanPng = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
  "base64",
);

test("tenant switching clears prior workspace upload state before exposing the new scope", async ({
  page,
}) => {
  test.skip(
    process.env.OMNIUS_E2E_BASE_URL !== undefined,
    "The deterministic two-tenant workflow belongs to the managed local fixture.",
  );
  await page.goto("/account");
  await page.getByLabel("Email").fill("person@example.test");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in" }).click();

  const workspace = page.getByLabel("Active workspace");
  await expect(workspace.locator("option")).toHaveCount(2);
  await expect(workspace).toHaveValue(primaryTenantId);
  await page.getByLabel("Choose file").setInputFiles({
    name: "tenant-one.png",
    mimeType: "image/png",
    buffer: cleanPng,
  });
  await expect(page.getByText("Upload is available.", { exact: true })).toBeVisible({
    timeout: 30_000,
  });

  await workspace.selectOption(secondaryTenantId);
  await expect(workspace).toHaveValue(secondaryTenantId);
  await expect(page).toHaveURL(new RegExp(`tenant=${secondaryTenantId}`, "u"));
  await expect(page.getByText("No file selected.", { exact: true })).toBeVisible();
  await expect(page.getByText("Upload is available.", { exact: true })).toHaveCount(0);

  const sessionTenant = await page.evaluate(async () => {
    const response = await fetch("/auth/session");
    const body = await response.json() as { readonly tenant_id?: string };
    return body.tenant_id;
  });
  expect(sessionTenant).toBe(secondaryTenantId);
});
