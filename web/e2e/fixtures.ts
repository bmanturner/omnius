import { readFileSync } from "node:fs";
import { createHash, randomBytes, sign } from "node:crypto";

import { expect, test as base } from "@playwright/test";
import type { APIRequestContext, APIResponse, Page } from "@playwright/test";

export const REFERENCE_SUBJECT_ID = "01890f2a-0000-7000-8000-000000000001";
export const REFERENCE_TENANT_ID = "01890f2a-0000-7000-8000-000000000002";
const JWT_ISSUER = "https://issuer.example.test";
const JWT_AUDIENCE = "omnius-api";
const FIXTURE_ORIGIN = `http://127.0.0.1:${Number.parseInt(process.env.OMNIUS_E2E_PORT ?? "4174", 10)}`;
const jwtPrivateKey = readFileSync(
  new URL("../../crates/auth-jwt/tests/test_rsa_key.pem", import.meta.url),
  "utf8",
);


export interface PkceAuthorizationRequest {
  readonly authorizationUrl: string;
  readonly codeVerifier: string;
}

export function createPkceAuthorizationRequest(options: {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly resource: string;
  readonly scope: string;
  readonly state: string;
}): PkceAuthorizationRequest {
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256").update(codeVerifier, "ascii").digest("base64url");
  const search = new URLSearchParams({
    client_id: options.clientId,
    redirect_uri: options.redirectUri,
    response_type: "code",
    response_mode: "query",
    scope: options.scope,
    resource: options.resource,
    state: options.state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
  return Object.freeze({
    authorizationUrl: `/oauth/authorize?${search.toString()}`,
    codeVerifier,
  });
}
export interface RuntimeMetadata {
  readonly application_version: string;
  readonly api_version: string;
  readonly build_revision: string;
  readonly capabilities: readonly string[];
  readonly contract_hash: string;
  readonly profile: string;
  readonly transports: {
    readonly api: string;
    readonly sse?: string;
    readonly websocket?: string;
  };
}

export interface OpenApiOperation {
  readonly operationId?: string;
}

export interface OpenApiDocument {
  readonly paths: Readonly<Record<string, Readonly<Record<string, OpenApiOperation>>>>;
}

interface CapabilityDescriptor {
  readonly id: string;
  readonly compiled: boolean;
  readonly runtime_available: boolean;
}

export interface CapabilityContract {
  readonly capabilities: readonly CapabilityDescriptor[];
  readonly contract_hash: string;
  readonly profile: string;
  readonly transports: {
    readonly api: string;
    readonly sse?: string;
    readonly websocket?: string;
  };
}

export const capabilityContract = JSON.parse(
  readFileSync(new URL("../../contracts/capabilities.json", import.meta.url), "utf8"),
) as CapabilityContract;

type BrowserFixtures = {
  readonly runtimeMetadata: RuntimeMetadata;
  readonly openApi: OpenApiDocument;
};

async function checkedJson<T>(response: APIResponse, label: string): Promise<T> {
  expect(response.ok(), `${label} must be served by the actual Axum process`).toBeTruthy();
  expect(response.headers()["content-type"]).toContain("application/json");
  return (await response.json()) as T;
}

export const test = base.extend<BrowserFixtures>({
  runtimeMetadata: async ({ request }, use) => {
    const response = await request.get("/api/_meta");
    await use(await checkedJson<RuntimeMetadata>(response, "runtime metadata"));
  },
  openApi: async ({ request }, use) => {
    const response = await request.get("/openapi.json");
    await use(await checkedJson<OpenApiDocument>(response, "OpenAPI document"));
  },
});

export { expect };

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

export function createBearerToken(options: { readonly expiresAt?: number } = {}): string {
  const issuedAt = Math.floor(Date.now() / 1000);
  const header = encodeJson({ alg: "RS256", kid: "profile-key", typ: "at+jwt" });
  const claims = encodeJson({
    sub: REFERENCE_SUBJECT_ID,
    iss: JWT_ISSUER,
    aud: [JWT_AUDIENCE],
    exp: options.expiresAt ?? issuedAt + 300,
    nbf: issuedAt - 5,
    iat: issuedAt - 5,
    kind: "user",
    tenant_id: REFERENCE_TENANT_ID,
    scope: "read:records write:records",
    assurance: "aal2",
  });
  const input = `${header}.${claims}`;
  const signature = sign("RSA-SHA256", Buffer.from(input), jwtPrivateKey).toString("base64url");
  return `${input}.${signature}`;
}

export async function authenticateBrowserSession(request: APIRequestContext): Promise<void> {
  const login = await request.post("/auth/login", {
    data: {
      identifier: "person@example.test",
      password: "correct horse battery staple",
    },
    headers: { origin: FIXTURE_ORIGIN },
  });
  if (login.status() !== 204) {
    throw new Error(`browser login returned ${login.status()}`);
  }
  const tenantSwitch = await request.post(`/tenants/${REFERENCE_TENANT_ID}/switch`, {
    headers: { origin: FIXTURE_ORIGIN },
  });
  if (tenantSwitch.status() !== 200) {
    throw new Error(`tenant switch returned ${tenantSwitch.status()}`);
  }
}

export async function authenticateBrowserPage(page: Page, returnTo = "/account"): Promise<void> {
  await page.goto(`/login?${new URLSearchParams({ returnTo }).toString()}`);
  await page.getByLabel("Email").fill("person@example.test");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(new RegExp(`${returnTo.replaceAll("/", "\\/")}(?:[?#]|$)`, "u"));
}

export async function createReferenceRecord(
  request: APIRequestContext,
  name: string,
  idempotencyKey: string,
): Promise<APIResponse> {
  return request.post("/reference-records", {
    data: { name },
    headers: {
      "content-type": "application/json",
      "idempotency-key": idempotencyKey,
      origin: FIXTURE_ORIGIN,
    },
  });
}

export function operationIds(openApi: OpenApiDocument): readonly string[] {
  return Object.values(openApi.paths)
    .flatMap((path) => Object.values(path))
    .flatMap((operation) =>
      operation.operationId === undefined ? [] : [operation.operationId],
    );
}
