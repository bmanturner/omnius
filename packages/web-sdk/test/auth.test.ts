import { describe, expect, it, vi } from "vitest";

import {
  BearerUnauthorizedError,
  createAuthManager,
  createBearerAuthManager,
  createOidcRedirectAuthManager,
  createRoutePrerequisites,
  createSessionAuthManager,
  validateAppRelativeLocation,
} from "../src/auth/index.js";
import type {
  AuthSessionState,
  CurrentPrincipalResult,
  IdentityTransitionLifecycle,
} from "../src/auth/index.js";
import {
  can,
  canAll,
  canAny,
  createPresentationAuthorization,
} from "../src/authorization/index.js";
import {
  createAuthSignalTestBus,
  createDeferred,
  createIdentityTransitionRecorder,
} from "../src/testing/index.js";

function authenticatedPrincipal(
  subject: string,
  permissions: readonly string[] = ["records.read"],
  tenantId: string | null = "tenant-1",
): CurrentPrincipalResult {
  return {
    status: 200,
    data: {
      subject_id: subject,
      kind: "user",
      authenticated_at: "2026-08-27T10:00:00Z",
      auth_method: "password",
      assurance: "aal1",
      scopes: ["openid"],
      presentation_permissions: permissions,
      tenant_id: tenantId,
    },
  };
}

function noIdentityLifecycle(): IdentityTransitionLifecycle {
  return Object.freeze({
    transition(): void {
      // Focused tests that do not inspect lifecycle ordering use an explicit host no-op.
    },
  });
}

describe("explicit auth factory", () => {
  it("creates an ambient-credential-free none mode only when explicitly declared", async () => {
    const manager = createAuthManager({ mode: "none" });
    expect(manager.mode).toBe("none");
    expect(manager.requestCredentials).toBe("omit");
    await expect(manager.getSession()).resolves.toEqual({
      status: "anonymous",
      mode: "none",
      reason: "none",
    });
  });
});

describe("session auth manager", () => {
  it("bootstraps, logs in, elevates, logs out, and logs out all through injected ports", async () => {
    let principalResult: CurrentPrincipalResult = {
      status: 401,
      data: { code: "SESSION_REQUIRED" },
    };
    const operations: string[] = [];
    const transitions = createIdentityTransitionRecorder();
    const signals = createAuthSignalTestBus();
    const manager = createSessionAuthManager({
      principal: {
        async getCurrentPrincipal(): Promise<CurrentPrincipalResult> {
          operations.push("principal");
          return principalResult;
        },
      },
      lifecycle: {
        async login(): Promise<void> {
          operations.push("login");
          principalResult = authenticatedPrincipal("principal-1");
        },
        async elevate(): Promise<void> {
          operations.push("elevate");
          principalResult = authenticatedPrincipal("principal-1", [
            "records.read",
            "records.write",
          ]);
        },
        async logout(): Promise<void> {
          operations.push("logout");
          principalResult = { status: 401, data: { code: "SESSION_REVOKED" } };
        },
        async logoutAll(): Promise<void> {
          operations.push("logout-all");
          principalResult = { status: 401, data: { code: "SESSION_REVOKED" } };
        },
      },
      identityLifecycle: transitions,
      crossTab: signals.createPort(),
      trustedOrigin: "https://app.example",
      sourceId: "tab-one",
      now: () => 10,
    });

    await expect(manager.getSession()).resolves.toMatchObject({
      status: "anonymous",
      problemCode: "SESSION_REQUIRED",
    });
    await expect(manager.login({ username: "reader" })).resolves.toMatchObject({
      status: "authenticated",
      principal: { subject: "principal-1" },
    });
    await expect(manager.elevate({ factor: "totp" })).resolves.toMatchObject({
      presentation: { permissions: ["records.read", "records.write"] },
    });
    await manager.logout();
    expect(manager.getSnapshot()).toMatchObject({ status: "anonymous", reason: "logged-out" });
    await manager.login({ username: "reader" });
    await manager.logoutAll();

    expect(operations).toEqual([
      "principal",
      "login",
      "principal",
      "elevate",
      "principal",
      "logout",
      "login",
      "principal",
      "logout-all",
    ]);
    expect(transitions.snapshot().map((transition) => transition.reason)).toEqual([
      "principal-change",
      "login",
      "privilege-elevation",
      "logout",
      "login",
      "logout-all",
    ]);
    expect(signals.snapshot().map((signal) => signal.reason)).toEqual([
      "login",
      "privilege-elevation",
      "logout",
      "login",
      "logout-all",
    ]);
    expect(JSON.stringify(signals.snapshot())).not.toMatch(/token|cookie|credential|secret/iu);
  });

  it("handles expiry once and converges another tab after credential-free logout", async () => {
    let principalResult = authenticatedPrincipal("principal-1");
    let principalCalls = 0;
    const bus = createAuthSignalTestBus();
    const principal = {
      async getCurrentPrincipal(): Promise<CurrentPrincipalResult> {
        principalCalls += 1;
        return principalResult;
      },
    };
    const lifecycle = {
      async login(): Promise<void> {
        principalResult = authenticatedPrincipal("principal-1");
      },
      async elevate(): Promise<void> {},
      async logout(): Promise<void> {
        principalResult = { status: 401, data: { code: "SESSION_EXPIRED" } };
      },
      async logoutAll(): Promise<void> {
        principalResult = { status: 401, data: { code: "SESSION_REVOKED" } };
      },
    };
    const first = createSessionAuthManager({
      principal,
      lifecycle,
      identityLifecycle: noIdentityLifecycle(),
      crossTab: bus.createPort(),
      trustedOrigin: "https://app.example",
      sourceId: "first",
    });
    const second = createSessionAuthManager({
      principal,
      lifecycle,
      identityLifecycle: noIdentityLifecycle(),
      crossTab: bus.createPort(),
      trustedOrigin: "https://app.example",
      sourceId: "second",
    });
    await Promise.all([first.getSession(), second.getSession()]);
    const converged = new Promise<AuthSessionState>((resolve) => {
      const unsubscribe = second.subscribe((state) => {
        if (state.status === "anonymous") {
          unsubscribe();
          resolve(state);
        }
      });
    });
    await first.logout();
    await expect(converged).resolves.toMatchObject({ status: "anonymous" });
    const callsAfterConvergence = principalCalls;
    await expect(second.getSession()).resolves.toMatchObject({
      status: "anonymous",
      problemCode: "SESSION_EXPIRED",
    });
    expect(principalCalls).toBe(callsAfterConvergence + 1);
  });

  it("adds fresh CSRF values only to unsafe requests on the trusted origin", async () => {
    let csrfCalls = 0;
    const manager = createSessionAuthManager({
      principal: {
        async getCurrentPrincipal(): Promise<CurrentPrincipalResult> {
          return { status: 401, data: { code: "SESSION_REQUIRED" } };
        },
      },
      lifecycle: {
        async login(): Promise<void> {},
        async elevate(): Promise<void> {},
        async logout(): Promise<void> {},
        async logoutAll(): Promise<void> {},
      },
      identityLifecycle: noIdentityLifecycle(),
      crossTab: createAuthSignalTestBus().createPort(),
      trustedOrigin: "https://app.example",
      sourceId: "csrf-tab",
      csrf: {
        headerName: "x-csrf-token",
        async getToken(): Promise<string> {
          csrfCalls += 1;
          return `csrf-${String(csrfCalls)}`;
        },
      },
    });

    await expect(
      manager.authorize({ url: new URL("https://app.example/api"), method: "GET" }),
    ).resolves.toEqual({ headers: {} });
    await expect(
      manager.authorize({ url: new URL("https://evil.example/api"), method: "POST" }),
    ).resolves.toEqual({ headers: {} });
    await expect(
      manager.authorize({ url: new URL("https://app.example/api"), method: "POST" }),
    ).resolves.toEqual({ headers: { "x-csrf-token": "csrf-1" } });
    await expect(
      manager.authorize({ url: new URL("https://app.example/api"), method: "DELETE" }),
    ).resolves.toEqual({ headers: { "x-csrf-token": "csrf-2" } });
    expect(csrfCalls).toBe(2);
  });
});

describe("bearer auth manager", () => {
  it("refreshes expiring tokens once for concurrent requests and exposes redacted diagnostics", async () => {
    const refresh = createDeferred<{ readonly accessToken: string; readonly expiresAt: number }>();
    let refreshCalls = 0;
    const diagnostics: unknown[] = [];
    const manager = createBearerAuthManager({
      audience: "records-api",
      now: () => 1_000,
      minimumValidityMs: 100,
      tokens: {
        async getAccessToken() {
          return { accessToken: "old-secret-token", expiresAt: 1_050 };
        },
        async refreshAccessToken() {
          refreshCalls += 1;
          return refresh.promise;
        },
        async clearAccessToken(): Promise<void> {},
      },
      principal: {
        async getCurrentPrincipal(): Promise<CurrentPrincipalResult> {
          return authenticatedPrincipal("principal-1");
        },
      },
      lifecycle: {
        async revoke(): Promise<void> {},
        async revokeAll(): Promise<void> {},
      },
      identityLifecycle: noIdentityLifecycle(),
      onDiagnostic: (diagnostic) => diagnostics.push(diagnostic),
    });
    const context = { url: new URL("https://api.example/records"), method: "GET" };
    const first = manager.authorize(context);
    const second = manager.authorize(context);
    refresh.resolve({ accessToken: "new-secret-token", expiresAt: 5_000 });

    await expect(Promise.all([first, second])).resolves.toEqual([
      { headers: { authorization: "Bearer new-secret-token" } },
      { headers: { authorization: "Bearer new-secret-token" } },
    ]);
    expect(refreshCalls).toBe(1);
    expect(manager.getDiagnostics()).toEqual({
      mode: "bearer",
      audience: "records-api",
      tokenState: "available",
      refreshInFlight: false,
    });
    expect(JSON.stringify(diagnostics)).not.toContain("secret-token");
  });

  it("retries one 401 after one refresh and never loops", async () => {
    let refreshCalls = 0;
    const attempts: number[] = [];
    const manager = createBearerAuthManager({
      audience: "records-api",
      now: () => 1_000,
      tokens: {
        async getAccessToken() {
          return { accessToken: "initial", expiresAt: 50_000 };
        },
        async refreshAccessToken() {
          refreshCalls += 1;
          return { accessToken: "refreshed", expiresAt: 50_000 };
        },
        async clearAccessToken(): Promise<void> {},
      },
      principal: {
        async getCurrentPrincipal(): Promise<CurrentPrincipalResult> {
          return authenticatedPrincipal("principal-1");
        },
      },
      lifecycle: {
        async revoke(): Promise<void> {},
        async revokeAll(): Promise<void> {},
      },
      identityLifecycle: noIdentityLifecycle(),
    });

    await expect(
      manager.executeAuthorized(
        { url: new URL("https://api.example/records"), method: "GET" },
        async (_authorization, attempt) => {
          attempts.push(attempt);
          throw new BearerUnauthorizedError();
        },
      ),
    ).rejects.toBeInstanceOf(BearerUnauthorizedError);
    expect(attempts).toEqual([0, 1]);
    expect(refreshCalls).toBe(1);
  });

  it("propagates cancellation to the sole refresh and revokes without storage or logging", async () => {
    let refreshSignal: AbortSignal | undefined;
    let cleared = 0;
    const consoleLog = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const storageRead = vi.fn(() => {
      throw new Error("browser storage must not be read");
    });
    Object.defineProperty(globalThis, "localStorage", {
      configurable: true,
      get: storageRead,
    });
    const manager = createBearerAuthManager({
      audience: "records-api",
      now: () => 1_000,
      minimumValidityMs: 100,
      tokens: {
        async getAccessToken() {
          return { accessToken: "expiring", expiresAt: 1_001 };
        },
        async refreshAccessToken(request) {
          refreshSignal = request.signal;
          return new Promise((_resolve, reject) => {
            request.signal?.addEventListener(
              "abort",
              () => reject(request.signal?.reason),
              { once: true },
            );
          });
        },
        async clearAccessToken(): Promise<void> {
          cleared += 1;
        },
      },
      principal: {
        async getCurrentPrincipal(): Promise<CurrentPrincipalResult> {
          return authenticatedPrincipal("principal-1");
        },
      },
      lifecycle: {
        async revoke(): Promise<void> {},
        async revokeAll(): Promise<void> {},
      },
      identityLifecycle: noIdentityLifecycle(),
    });
    const controller = new AbortController();
    const authorization = manager.authorize({
      url: new URL("https://api.example/records"),
      method: "GET",
      signal: controller.signal,
    });
    await Promise.resolve();
    await Promise.resolve();
    controller.abort(new DOMException("cancelled", "AbortError"));
    await expect(authorization).rejects.toMatchObject({ name: "AbortError" });
    expect(refreshSignal?.aborted).toBe(true);

    await manager.logout();
    expect(cleared).toBe(1);
    expect(storageRead).not.toHaveBeenCalled();
    expect(consoleLog).not.toHaveBeenCalled();
    consoleLog.mockRestore();
    Reflect.deleteProperty(globalThis, "localStorage");
  });
});

describe("OIDC redirects and route prerequisites", () => {
  const locations = {
    origin: "https://app.example",
    approvedPathPrefixes: ["/app", "/login", "/select-tenant", "/denied"],
  } as const;

  it("rejects unsafe OIDC return locations before delegating to the backend", async () => {
    let principalResult: CurrentPrincipalResult = {
      status: 401,
      data: { code: "SESSION_REQUIRED" },
    };
    const begin = vi.fn(async ({ returnTo }: { readonly returnTo: string }) => ({
      redirectTo: `https://identity.example/authorize?returnTo=${encodeURIComponent(returnTo)}`,
    }));
    const manager = createOidcRedirectAuthManager({
      principal: {
        async getCurrentPrincipal(): Promise<CurrentPrincipalResult> {
          return principalResult;
        },
      },
      lifecycle: {
        async elevate(): Promise<void> {},
        async logout(): Promise<void> {},
        async logoutAll(): Promise<void> {},
      },
      oidc: {
        beginLogin: begin,
        async completeCallback(): Promise<void> {
          principalResult = authenticatedPrincipal("principal-1");
        },
        async listLinkedIdentities() {
          return [{ id: "linked-1", provider: "example" }];
        },
        async unlinkIdentity(): Promise<void> {},
      },
      identityLifecycle: noIdentityLifecycle(),
      crossTab: createAuthSignalTestBus().createPort(),
      trustedOrigin: "https://app.example",
      returnLocations: locations,
      sourceId: "oidc-tab",
    });

    await expect(manager.beginOidcLogin("example", "/app/records?view=all")).resolves.toMatchObject({
      redirectTo: expect.stringMatching(/^https:\/\/identity\.example\//u),
    });
    await expect(manager.completeOidcCallback({ callback: "opaque-host-input" })).resolves.toMatchObject({
      status: "authenticated",
    });
    expect(begin).toHaveBeenCalledTimes(1);
    for (const unsafe of [
      "https://evil.example/app",
      "//evil.example/app",
      "/\\evil",
      "/%2f%2fevil.example",
      "/app/%0aheader",
      "/not-approved",
    ]) {
      await expect(manager.beginOidcLogin("example", unsafe)).rejects.toBeInstanceOf(TypeError);
    }
    expect(begin).toHaveBeenCalledTimes(1);
  });

  it("keeps permission checks UX-only and returns loading, safe redirects, allow, and loop denial", () => {
    const presentation = createPresentationAuthorization(
      ["records.read"],
      [{ permission: "records.write", context: { recordId: "record-1" } }],
    );
    expect(can(presentation, "records.read")).toBe(true);
    expect(can(presentation, "records.write", { recordId: "record-1" })).toBe(true);
    expect(can(presentation, "records.write", { recordId: "record-2" })).toBe(false);
    expect(canAny(presentation, ["records.delete", "records.read"])).toBe(true);
    expect(canAll(presentation, ["records.read", "records.delete"])).toBe(false);

    const directBackendOperation = (): never => {
      const denial = new Error("backend denied independently") as Error & { status: number };
      denial.status = 403;
      throw denial;
    };
    expect(directBackendOperation).toThrow(expect.objectContaining({ status: 403 }));

    const prerequisites = createRoutePrerequisites({
      locations,
      loginLocation: "/login",
      authenticatedHomeLocation: "/app",
      tenantSelectionLocation: "/select-tenant",
      permissionDeniedLocation: "/denied",
    });
    expect(
      prerequisites.requireAuthenticated({
        session: { status: "loading", mode: "session", reason: "initial" },
        currentLocation: "/app/records",
      }),
    ).toEqual({ status: "loading", reason: "session" });
    expect(
      prerequisites.requireAuthenticated({
        session: {
          status: "anonymous",
          mode: "session",
          reason: "not-authenticated",
        },
        currentLocation: "/app/records?view=all",
      }),
    ).toEqual({
      status: "redirect",
      to: "/login?returnTo=%2Fapp%2Frecords%3Fview%3Dall",
      returnTo: "/app/records?view=all",
    });
    expect(
      prerequisites.requireAuthenticated({
        session: {
          status: "anonymous",
          mode: "session",
          reason: "not-authenticated",
        },
        currentLocation: "/login",
      }),
    ).toEqual({ status: "deny", reason: "redirect-loop" });
    const session: AuthSessionState = {
      status: "authenticated",
      mode: "session",
      principal: { subject: "principal-1", kind: "user" },
      session: {
        authenticatedAt: "2026-08-27T10:00:00Z",
        authenticationMethod: "password",
        assurance: "aal1",
      },
      presentation,
      scopes: ["openid"],
      tenant: { id: "tenant-1" },
    };
    expect(
      prerequisites.requirePermission(
        { session, currentLocation: "/app/records" },
        { allOf: ["records.read"] },
      ),
    ).toEqual({ status: "allow" });
  });

  it("validates only approved same-origin app-relative destinations", () => {
    expect(validateAppRelativeLocation("/app/records#details", locations)).toBe(
      "/app/records#details",
    );
    expect(() => validateAppRelativeLocation("//evil.example", locations)).toThrow(TypeError);
    expect(() => validateAppRelativeLocation("https://evil.example", locations)).toThrow(TypeError);
    expect(() => validateAppRelativeLocation("/app\\evil", locations)).toThrow(TypeError);
  });
});
