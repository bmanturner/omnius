import { createPresentationAuthorization } from "../authorization/index.js";
import type {
  AuthDiagnosticListener,
  AuthManager,
  AuthRequestAuthorization,
  AuthRequestContext,
  AuthSessionListener,
  AuthSessionState,
  AuthenticatedSession,
  CurrentPrincipalPayload,
  CurrentPrincipalPort,
  CurrentPrincipalResult,
  GetSessionOptions,
  IdentityTransitionLifecycle,
  IdentityTransitionReason,
} from "./types.js";

const EMPTY_AUTHORIZATION: AuthRequestAuthorization = Object.freeze({
  headers: Object.freeze({}),
});

const SAFE_SESSION_METHODS: Readonly<Record<string, true>> = Object.freeze({
  GET: true,
  HEAD: true,
  OPTIONS: true,
  TRACE: true,
});

export interface SessionOperationOptions {
  readonly signal?: AbortSignal;
}

export interface SessionLifecyclePort<TLoginInput = unknown, TElevationInput = unknown> {
  login(input: TLoginInput, options?: SessionOperationOptions): Promise<void>;
  elevate(input: TElevationInput, options?: SessionOperationOptions): Promise<void>;
  logout(options?: SessionOperationOptions): Promise<void>;
  logoutAll(options?: SessionOperationOptions): Promise<void>;
}

export interface SessionCsrfPort {
  readonly headerName: string;
  getToken(options?: SessionOperationOptions): Promise<string>;
}

export type CrossTabAuthSignalReason =
  | "login"
  | "privilege-elevation"
  | "logout"
  | "logout-all";

/** Deliberately credential-free signal. No extension bag is accepted or emitted. */
export interface CrossTabAuthSignal {
  readonly version: 1;
  readonly type: "auth-session-changed";
  readonly reason: CrossTabAuthSignalReason;
  readonly sourceId: string;
  readonly issuedAt: number;
}

/** Injectable BroadcastChannel-like boundary. Implementations must not persist messages. */
export interface CrossTabAuthSignalPort {
  publish(signal: CrossTabAuthSignal): void;
  subscribe(listener: (signal: unknown) => void): () => void;
  close?(): void;
}

export interface SessionModeAuthManager<
  TMode extends "session" | "oidc-redirect",
  TLoginInput = unknown,
  TElevationInput = unknown,
> extends AuthManager {
  readonly mode: TMode;
  login(input: TLoginInput, options?: SessionOperationOptions): Promise<AuthenticatedSession>;
  elevate(
    input: TElevationInput,
    options?: SessionOperationOptions,
  ): Promise<AuthenticatedSession>;
  logout(options?: SessionOperationOptions): Promise<void>;
  logoutAll(options?: SessionOperationOptions): Promise<void>;
}

export type SessionAuthManager<TLoginInput = unknown, TElevationInput = unknown> =
  SessionModeAuthManager<"session", TLoginInput, TElevationInput>;

export interface SessionAuthManagerConfiguration<
  TLoginInput = unknown,
  TElevationInput = unknown,
> {
  readonly principal: CurrentPrincipalPort;
  readonly lifecycle: SessionLifecyclePort<TLoginInput, TElevationInput>;
  readonly identityLifecycle: IdentityTransitionLifecycle;
  readonly crossTab: CrossTabAuthSignalPort;
  readonly trustedOrigin: string | URL;
  readonly credentials?: RequestCredentials;
  readonly csrf?: SessionCsrfPort;
  readonly now?: () => number;
  readonly sourceId?: string;
  readonly onDiagnostic?: AuthDiagnosticListener;
}

export class CurrentPrincipalRequestError extends Error {
  override readonly name = "CurrentPrincipalRequestError";
  readonly status: number;

  constructor(status: number) {
    super(`The current-principal operation failed with HTTP ${String(status)}.`);
    this.status = status;
  }
}

export class AuthIdentityTransitionError extends Error {
  override readonly name = "AuthIdentityTransitionError";

  constructor(message: string) {
    super(message);
  }
}

function validatePublicString(value: string, name: string): string {
  if (value.length === 0 || value.trim() !== value) {
    throw new TypeError(`${name} must be a non-empty trimmed value.`);
  }
  return value;
}

function normalizePrincipalPayload(
  payload: CurrentPrincipalPayload,
  mode: "session" | "bearer" | "oidc-redirect",
): AuthenticatedSession {
  const subject = validatePublicString(payload.subject_id, "Principal subject");
  const authenticatedAt = validatePublicString(
    payload.authenticated_at,
    "Session authentication time",
  );
  if (!Number.isFinite(Date.parse(authenticatedAt))) {
    throw new TypeError("Session authentication time must be an ISO-compatible timestamp.");
  }
  if (payload.expires_at !== undefined && !Number.isFinite(Date.parse(payload.expires_at))) {
    throw new TypeError("Session expiry time must be an ISO-compatible timestamp.");
  }
  const scopes = Object.freeze(
    payload.scopes.map((scope) => validatePublicString(scope, "Presentation scope")),
  );
  const permissions = payload.presentation_permissions ?? scopes;
  const presentation = createPresentationAuthorization(
    permissions,
    payload.resource_permissions?.map((grant) => ({
      permission: grant.permission,
      context: grant.context,
    })),
  );
  const tenantPayload = payload.tenant;
  const tenantId = tenantPayload?.id ?? payload.tenant_id ?? null;
  if (
    tenantPayload !== undefined &&
    tenantPayload !== null &&
    payload.tenant_id !== undefined &&
    payload.tenant_id !== null &&
    tenantPayload.id !== payload.tenant_id
  ) {
    throw new TypeError("Current-principal tenant identifiers must agree.");
  }
  const tenant =
    tenantId === null
      ? null
      : Object.freeze({
          id: validatePublicString(tenantId, "Tenant ID"),
          ...(tenantPayload?.display_name === undefined
            ? {}
            : {
                displayName: validatePublicString(
                  tenantPayload.display_name,
                  "Tenant display name",
                ),
              }),
        });
  return Object.freeze({
    status: "authenticated",
    mode,
    principal: Object.freeze({
      subject,
      kind: validatePublicString(payload.kind, "Principal kind"),
      ...(payload.display_name === undefined
        ? {}
        : {
            displayName: validatePublicString(payload.display_name, "Principal display name"),
          }),
    }),
    session: Object.freeze({
      authenticatedAt,
      authenticationMethod: validatePublicString(
        payload.auth_method,
        "Session authentication method",
      ),
      assurance: validatePublicString(payload.assurance, "Session assurance"),
      ...(payload.expires_at === undefined ? {} : { expiresAt: payload.expires_at }),
    }),
    presentation,
    scopes,
    tenant,
  });
}

function unauthenticatedProblemCode(result: CurrentPrincipalResult): string | undefined {
  if (result.status !== 401 || typeof result.data !== "object" || result.data === null) {
    return undefined;
  }
  const code = Reflect.get(result.data, "code");
  return typeof code === "string" && code.length > 0 ? code : undefined;
}

export function normalizeCurrentPrincipalResult(
  result: CurrentPrincipalResult,
  mode: "session" | "bearer" | "oidc-redirect",
  previousStatus: AuthSessionState["status"] = "loading",
): AuthSessionState {
  if (result.status === 200) {
    return normalizePrincipalPayload(result.data as CurrentPrincipalPayload, mode);
  }
  if (result.status === 401) {
    const problemCode = unauthenticatedProblemCode(result);
    return Object.freeze({
      status: "anonymous",
      mode,
      reason: previousStatus === "authenticated" ? "expired-or-revoked" : "not-authenticated",
      ...(problemCode === undefined ? {} : { problemCode }),
    });
  }
  throw new CurrentPrincipalRequestError(result.status);
}

function sessionsEquivalent(left: AuthSessionState, right: AuthSessionState): boolean {
  if (left.status !== right.status) {
    return false;
  }
  if (left.status !== "authenticated" || right.status !== "authenticated") {
    return JSON.stringify(left) === JSON.stringify(right);
  }
  return (
    left.principal.subject === right.principal.subject &&
    left.tenant?.id === right.tenant?.id &&
    left.session.authenticatedAt === right.session.authenticatedAt &&
    JSON.stringify(left.scopes) === JSON.stringify(right.scopes) &&
    JSON.stringify(left.presentation) === JSON.stringify(right.presentation)
  );
}

function isCrossTabAuthSignal(value: unknown): value is CrossTabAuthSignal {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const reason = Reflect.get(value, "reason");
  return (
    Reflect.get(value, "version") === 1 &&
    Reflect.get(value, "type") === "auth-session-changed" &&
    (reason === "login" ||
      reason === "privilege-elevation" ||
      reason === "logout" ||
      reason === "logout-all") &&
    typeof Reflect.get(value, "sourceId") === "string" &&
    typeof Reflect.get(value, "issuedAt") === "number"
  );
}

function trustedOrigin(value: string | URL): string {
  const parsed = value instanceof URL ? value : new URL(value);
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
    parsed.username.length > 0 ||
    parsed.password.length > 0 ||
    parsed.pathname !== "/" ||
    parsed.search.length > 0 ||
    parsed.hash.length > 0
  ) {
    throw new TypeError("The session trusted origin must be a credential-free HTTP(S) origin.");
  }
  return parsed.origin;
}

function notifyDiagnostic(
  listener: AuthDiagnosticListener | undefined,
  diagnostic: Parameters<AuthDiagnosticListener>[0],
): void {
  try {
    listener?.(Object.freeze(diagnostic));
  } catch {
    // Diagnostics must never affect authentication behavior.
  }
}

function abortIfRequested(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw signal.reason ?? new DOMException("Aborted", "AbortError");
  }
}

function createSourceId(sourceId: string | undefined): string {
  if (sourceId !== undefined) {
    return validatePublicString(sourceId, "Cross-tab source ID");
  }
  if (typeof globalThis.crypto?.randomUUID !== "function") {
    throw new TypeError("Session auth requires an injected sourceId when crypto.randomUUID is unavailable.");
  }
  return globalThis.crypto.randomUUID();
}

export function createSessionModeAuthManager<
  TMode extends "session" | "oidc-redirect",
  TLoginInput = unknown,
  TElevationInput = unknown,
>(
  configuration: SessionAuthManagerConfiguration<TLoginInput, TElevationInput>,
  mode: TMode,
): SessionModeAuthManager<TMode, TLoginInput, TElevationInput> {
  const origin = trustedOrigin(configuration.trustedOrigin);
  const sourceId = createSourceId(configuration.sourceId);
  const now = configuration.now ?? Date.now;
  const requestCredentials = configuration.credentials ?? "same-origin";
  let state: AuthSessionState = Object.freeze({
    status: "loading",
    mode,
    reason: "initial",
  });
  let disposed = false;
  let mutationActive = false;
  let crossTabRevalidation: Promise<void> | undefined;
  const listeners = new Set<AuthSessionListener>();

  const publishState = (next: AuthSessionState): void => {
    state = next;
    for (const listener of listeners) {
      try {
        listener(next);
      } catch {
        // A view subscriber must not break the auth state machine.
      }
    }
  };

  const fetchSession = async (options: GetSessionOptions = {}): Promise<AuthSessionState> => {
    abortIfRequested(options.signal);
    const result = await configuration.principal.getCurrentPrincipal(options);
    abortIfRequested(options.signal);
    return normalizeCurrentPrincipalResult(result, mode, state.status);
  };

  const transitionTo = async (
    previous: AuthSessionState,
    next: AuthSessionState,
    reason: IdentityTransitionReason,
    signal: AbortSignal | undefined,
  ): Promise<void> => {
    const loading: AuthSessionState = Object.freeze({
      status: "loading",
      mode,
      reason: reason === "cross-tab" ? "cross-tab-revalidation" : "identity-transition",
    });
    publishState(loading);
    try {
      await configuration.identityLifecycle.transition({
        reason,
        previous,
        next,
        ...(signal === undefined ? {} : { signal }),
      });
      abortIfRequested(signal);
      publishState(next);
    } catch (error: unknown) {
      publishState(
        Object.freeze({
          status: "error",
          mode,
          reason: "identity-transition-failed",
        }),
      );
      throw error;
    }
  };

  const getSession = async (options: GetSessionOptions = {}): Promise<AuthSessionState> => {
    const previous = state;
    try {
      const next = await fetchSession(options);
      if (sessionsEquivalent(previous, next)) {
        publishState(next);
        return next;
      }
      const transitionReason: IdentityTransitionReason =
        next.status === "anonymous" && previous.status === "authenticated"
          ? "session-expired"
          : previous.status === "authenticated" &&
              next.status === "authenticated" &&
              previous.principal.subject === next.principal.subject &&
              previous.tenant?.id === next.tenant?.id
            ? "permission-change"
            : "principal-change";
      await transitionTo(previous, next, transitionReason, options.signal);
      return next;
    } catch (error: unknown) {
      if (state.status !== "error") {
        publishState(
          Object.freeze({ status: "error", mode, reason: "bootstrap-failed" }),
        );
      }
      notifyDiagnostic(configuration.onDiagnostic, {
        mode,
        event: "bootstrap-failed",
        category: options.signal?.aborted === true ? "aborted" : "provider",
      });
      throw error;
    }
  };

  const publishCrossTab = (reason: CrossTabAuthSignalReason): void => {
    configuration.crossTab.publish(
      Object.freeze({
        version: 1,
        type: "auth-session-changed",
        reason,
        sourceId,
        issuedAt: now(),
      }),
    );
  };

  const runAuthenticatedMutation = async (
    operation: () => Promise<void>,
    reason: "login" | "privilege-elevation",
    options: SessionOperationOptions,
  ): Promise<AuthenticatedSession> => {
    if (mutationActive) {
      throw new AuthIdentityTransitionError("An authentication transition is already active.");
    }
    mutationActive = true;
    const previous = state;
    publishState(
      Object.freeze({ status: "loading", mode, reason: "identity-transition" }),
    );
    let backendChanged = false;
    try {
      abortIfRequested(options.signal);
      await operation();
      backendChanged = true;
      const next = await fetchSession(options);
      if (next.status !== "authenticated") {
        throw new AuthIdentityTransitionError(
          "The current-principal operation did not confirm the authenticated transition.",
        );
      }
      await configuration.identityLifecycle.transition({
        reason,
        previous,
        next,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      abortIfRequested(options.signal);
      publishState(next);
      publishCrossTab(reason);
      return next;
    } catch (error: unknown) {
      publishState(
        backendChanged
          ? Object.freeze({
              status: "error",
              mode,
              reason: "identity-transition-failed",
            })
          : previous,
      );
      throw error;
    } finally {
      mutationActive = false;
    }
  };

  const runLogoutMutation = async (
    operation: () => Promise<void>,
    reason: "logout" | "logout-all",
    options: SessionOperationOptions,
  ): Promise<void> => {
    if (mutationActive) {
      throw new AuthIdentityTransitionError("An authentication transition is already active.");
    }
    mutationActive = true;
    const previous = state;
    publishState(
      Object.freeze({ status: "loading", mode, reason: "identity-transition" }),
    );
    let backendChanged = false;
    try {
      abortIfRequested(options.signal);
      await operation();
      backendChanged = true;
      const next: AuthSessionState = Object.freeze({
        status: "anonymous",
        mode,
        reason: "logged-out",
      });
      await configuration.identityLifecycle.transition({
        reason,
        previous,
        next,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      abortIfRequested(options.signal);
      publishState(next);
      publishCrossTab(reason);
    } catch (error: unknown) {
      publishState(
        backendChanged
          ? Object.freeze({
              status: "error",
              mode,
              reason: "identity-transition-failed",
            })
          : previous,
      );
      throw error;
    } finally {
      mutationActive = false;
    }
  };

  const unsubscribeCrossTab = configuration.crossTab.subscribe((value) => {
    if (
      disposed ||
      !isCrossTabAuthSignal(value) ||
      value.sourceId === sourceId ||
      crossTabRevalidation !== undefined
    ) {
      return;
    }
    const previous = state;
    publishState(
      Object.freeze({
        status: "loading",
        mode,
        reason: "cross-tab-revalidation",
      }),
    );
    crossTabRevalidation = (async () => {
      try {
        const next = await fetchSession();
        await configuration.identityLifecycle.transition({
          reason: "cross-tab",
          previous,
          next,
        });
        publishState(next);
      } catch {
        publishState(
          Object.freeze({ status: "error", mode, reason: "bootstrap-failed" }),
        );
        notifyDiagnostic(configuration.onDiagnostic, {
          mode,
          event: "cross-tab-revalidation-failed",
          category: "provider",
        });
      } finally {
        crossTabRevalidation = undefined;
      }
    })();
  });

  return Object.freeze({
    mode,
    requestCredentials,
    async authorize(context: AuthRequestContext): Promise<AuthRequestAuthorization> {
      const method = context.method.toUpperCase();
      if (
        configuration.csrf === undefined ||
        SAFE_SESSION_METHODS[method] === true ||
        context.url.origin !== origin
      ) {
        return EMPTY_AUTHORIZATION;
      }
      abortIfRequested(context.signal);
      const token = await configuration.csrf.getToken(
        context.signal === undefined ? {} : { signal: context.signal },
      );
      abortIfRequested(context.signal);
      if (token.length === 0 || token.trim() !== token) {
        throw new TypeError("The CSRF port returned an empty or malformed token.");
      }
      const headers = new Headers({ [configuration.csrf.headerName]: token });
      const normalizedName = [...headers.keys()][0];
      if (normalizedName === undefined) {
        throw new TypeError("The CSRF header name is invalid.");
      }
      return Object.freeze({
        headers: Object.freeze({ [normalizedName]: token }),
      });
    },
    getSnapshot(): AuthSessionState {
      return state;
    },
    getSession,
    subscribe(listener: AuthSessionListener): () => void {
      if (disposed) {
        throw new AuthIdentityTransitionError("The authentication manager is disposed.");
      }
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    async login(
      input: TLoginInput,
      options: SessionOperationOptions = {},
    ): Promise<AuthenticatedSession> {
      return runAuthenticatedMutation(
        () => configuration.lifecycle.login(input, options),
        "login",
        options,
      );
    },
    async elevate(
      input: TElevationInput,
      options: SessionOperationOptions = {},
    ): Promise<AuthenticatedSession> {
      return runAuthenticatedMutation(
        () => configuration.lifecycle.elevate(input, options),
        "privilege-elevation",
        options,
      );
    },
    async logout(options: SessionOperationOptions = {}): Promise<void> {
      await runLogoutMutation(
        () => configuration.lifecycle.logout(options),
        "logout",
        options,
      );
    },
    async logoutAll(options: SessionOperationOptions = {}): Promise<void> {
      await runLogoutMutation(
        () => configuration.lifecycle.logoutAll(options),
        "logout-all",
        options,
      );
    },
    dispose(): void {
      if (disposed) {
        return;
      }
      disposed = true;
      unsubscribeCrossTab();
      configuration.crossTab.close?.();
      listeners.clear();
    },
  });
}

export function createSessionAuthManager<TLoginInput = unknown, TElevationInput = unknown>(
  configuration: SessionAuthManagerConfiguration<TLoginInput, TElevationInput>,
): SessionAuthManager<TLoginInput, TElevationInput> {
  return createSessionModeAuthManager(configuration, "session");
}
