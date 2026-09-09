import type {
  AuthDiagnosticListener,
  AuthManager,
  AuthRequestAuthorization,
  AuthRequestContext,
  AuthSessionListener,
  AuthSessionState,
  CurrentPrincipalPort,
  GetSessionOptions,
  IdentityTransitionLifecycle,
} from "./types.js";
import { normalizeCurrentPrincipalResult } from "./session.js";

export interface BearerTokenResult {
  readonly accessToken: string;
  /** Absolute Unix epoch time in milliseconds. */
  readonly expiresAt: number;
}

export interface BearerTokenRequest {
  readonly audience: string;
  readonly signal?: AbortSignal;
}

/** Host-owned token source. The SDK never persists the returned credential. */
export interface BearerTokenProvider {
  getAccessToken(request: BearerTokenRequest): Promise<BearerTokenResult | null>;
  refreshAccessToken(request: BearerTokenRequest): Promise<BearerTokenResult | null>;
  clearAccessToken(request: BearerTokenRequest): void | Promise<void>;
}

/** Backend/token-provider lifecycle that revokes without exposing credentials to diagnostics. */
export interface BearerLifecyclePort {
  revoke(request: BearerTokenRequest): Promise<void>;
  revokeAll(request: BearerTokenRequest): Promise<void>;
}

export type BearerAuthorizedOperation<TValue> = (
  authorization: AuthRequestAuthorization,
  attempt: 0 | 1,
  signal?: AbortSignal,
) => Promise<TValue>;

export interface BearerAuthManager extends AuthManager {
  readonly mode: "bearer";
  readonly audience: string;
  executeAuthorized<TValue>(
    context: AuthRequestContext,
    operation: BearerAuthorizedOperation<TValue>,
  ): Promise<TValue>;
  logout(options?: GetSessionOptions): Promise<void>;
  logoutAll(options?: GetSessionOptions): Promise<void>;
  getDiagnostics(): Readonly<BearerDiagnostics>;
}

export interface BearerDiagnostics {
  readonly mode: "bearer";
  readonly audience: string;
  readonly tokenState: "unavailable" | "available" | "expiring" | "expired";
  readonly refreshInFlight: boolean;
}

export interface BearerAuthManagerConfiguration {
  readonly audience: string;
  readonly tokens: BearerTokenProvider;
  readonly principal: CurrentPrincipalPort;
  readonly lifecycle: BearerLifecyclePort;
  readonly identityLifecycle: IdentityTransitionLifecycle;
  readonly minimumValidityMs?: number;
  readonly now?: () => number;
  readonly isUnauthorized?: (error: unknown) => boolean;
  readonly onDiagnostic?: AuthDiagnosticListener;
}

export class BearerUnauthorizedError extends Error {
  override readonly name = "BearerUnauthorizedError";
  readonly status = 401;

  constructor() {
    super("The bearer credential was rejected.");
  }
}

interface RefreshFlight {
  readonly controller: AbortController;
  readonly promise: Promise<BearerTokenResult | null>;
  waiters: number;
  settled: boolean;
}

const EMPTY_AUTHORIZATION: AuthRequestAuthorization = Object.freeze({
  headers: Object.freeze({}),
});

function validateAudience(audience: string): string {
  if (audience.length === 0 || audience.trim() !== audience || audience.length > 512) {
    throw new TypeError("Bearer audience must be a non-empty trimmed value.");
  }
  return audience;
}

function validateTokenResult(result: BearerTokenResult): Readonly<BearerTokenResult> {
  if (
    result.accessToken.length === 0 ||
    result.accessToken.trim() !== result.accessToken ||
    /[\r\n]/u.test(result.accessToken)
  ) {
    throw new TypeError("The bearer token provider returned a malformed credential.");
  }
  if (!Number.isFinite(result.expiresAt) || result.expiresAt < 0) {
    throw new TypeError("The bearer token provider returned an invalid expiry time.");
  }
  return Object.freeze({
    accessToken: result.accessToken,
    expiresAt: result.expiresAt,
  });
}

function abortIfRequested(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw signal.reason ?? new DOMException("Aborted", "AbortError");
  }
}

function defaultUnauthorizedClassifier(error: unknown): boolean {
  if (error instanceof BearerUnauthorizedError) {
    return true;
  }
  return (
    typeof error === "object" &&
    error !== null &&
    Reflect.get(error, "status") === 401
  );
}

function notifyDiagnostic(
  listener: AuthDiagnosticListener | undefined,
  diagnostic: Parameters<AuthDiagnosticListener>[0],
): void {
  try {
    listener?.(Object.freeze(diagnostic));
  } catch {
    // Diagnostics must never affect credential behavior.
  }
}

function authorizationForToken(
  token: Readonly<BearerTokenResult> | null,
): AuthRequestAuthorization {
  if (token === null) {
    return EMPTY_AUTHORIZATION;
  }
  return Object.freeze({
    headers: Object.freeze({ authorization: `Bearer ${token.accessToken}` }),
  });
}

export function createBearerAuthManager(
  configuration: BearerAuthManagerConfiguration,
): BearerAuthManager {
  const audience = validateAudience(configuration.audience);
  const now = configuration.now ?? Date.now;
  const minimumValidityMs = configuration.minimumValidityMs ?? 30_000;
  if (!Number.isFinite(minimumValidityMs) || minimumValidityMs < 0) {
    throw new RangeError("Bearer minimumValidityMs must be a finite non-negative number.");
  }
  const isUnauthorized = configuration.isUnauthorized ?? defaultUnauthorizedClassifier;
  let cachedToken: Readonly<BearerTokenResult> | null | undefined;
  let refreshFlight: RefreshFlight | undefined;
  let state: AuthSessionState = Object.freeze({
    status: "loading",
    mode: "bearer",
    reason: "initial",
  });
  let disposed = false;
  const listeners = new Set<AuthSessionListener>();

  const publishState = (next: AuthSessionState): void => {
    state = next;
    for (const listener of listeners) {
      try {
        listener(next);
      } catch {
        // A view subscriber must not break bearer credential state.
      }
    }
  };

  const tokenRequest = (signal: AbortSignal | undefined): BearerTokenRequest =>
    Object.freeze({
      audience,
      ...(signal === undefined ? {} : { signal }),
    });

  const tokenIsUsable = (token: Readonly<BearerTokenResult>): boolean =>
    token.expiresAt > now() + minimumValidityMs;

  const startRefresh = (): RefreshFlight => {
    const controller = new AbortController();
    let flight: RefreshFlight;
    const promise = (async (): Promise<BearerTokenResult | null> => {
      try {
        const result = await configuration.tokens.refreshAccessToken(
          tokenRequest(controller.signal),
        );
        const normalized = result === null ? null : validateTokenResult(result);
        cachedToken = normalized;
        notifyDiagnostic(configuration.onDiagnostic, {
          mode: "bearer",
          event: "token-refreshed",
          audience,
        });
        return normalized;
      } catch (error: unknown) {
        notifyDiagnostic(configuration.onDiagnostic, {
          mode: "bearer",
          event: "token-refresh-failed",
          audience,
          category: controller.signal.aborted ? "aborted" : "provider",
        });
        throw error;
      }
    })().finally(() => {
      flight.settled = true;
      if (refreshFlight === flight) {
        refreshFlight = undefined;
      }
    });
    flight = { controller, promise, waiters: 0, settled: false };
    refreshFlight = flight;
    return flight;
  };

  const joinRefresh = (signal: AbortSignal | undefined): Promise<BearerTokenResult | null> => {
    abortIfRequested(signal);
    const flight = refreshFlight ?? startRefresh();
    flight.waiters += 1;
    return new Promise<BearerTokenResult | null>((resolve, reject) => {
      let released = false;
      const release = (): void => {
        if (released) {
          return;
        }
        released = true;
        signal?.removeEventListener("abort", abort);
        flight.waiters -= 1;
        if (flight.waiters === 0 && !flight.settled) {
          flight.controller.abort(new DOMException("All refresh waiters aborted", "AbortError"));
        }
      };
      const abort = (): void => {
        release();
        reject(signal?.reason ?? new DOMException("Aborted", "AbortError"));
      };
      if (signal?.aborted === true) {
        abort();
        return;
      }
      signal?.addEventListener("abort", abort, { once: true });
      void flight.promise.then(
        (result) => {
          release();
          resolve(result);
        },
        (error: unknown) => {
          release();
          reject(error);
        },
      );
    });
  };

  const getUsableToken = async (
    signal: AbortSignal | undefined,
    forceRefresh: boolean,
  ): Promise<Readonly<BearerTokenResult> | null> => {
    abortIfRequested(signal);
    if (forceRefresh) {
      return joinRefresh(signal);
    }
    if (cachedToken !== undefined && cachedToken !== null && tokenIsUsable(cachedToken)) {
      return cachedToken;
    }
    if (cachedToken === null) {
      return null;
    }
    if (cachedToken === undefined) {
      const supplied = await configuration.tokens.getAccessToken(tokenRequest(signal));
      abortIfRequested(signal);
      cachedToken = supplied === null ? null : validateTokenResult(supplied);
      if (cachedToken === null) {
        notifyDiagnostic(configuration.onDiagnostic, {
          mode: "bearer",
          event: "token-unavailable",
          audience,
        });
        return null;
      }
      if (tokenIsUsable(cachedToken)) {
        return cachedToken;
      }
    }
    return joinRefresh(signal);
  };

  const authorize = async (
    context: AuthRequestContext,
  ): Promise<AuthRequestAuthorization> =>
    authorizationForToken(await getUsableToken(context.signal, false));

  const getSession = async (options: GetSessionOptions = {}): Promise<AuthSessionState> => {
    const previous = state;
    try {
      let result = await configuration.principal.getCurrentPrincipal(options);
      if (result.status === 401) {
        const refreshed = await getUsableToken(options.signal, true);
        if (refreshed !== null) {
          result = await configuration.principal.getCurrentPrincipal(options);
        }
      }
      const next = normalizeCurrentPrincipalResult(result, "bearer", previous.status);
      if (JSON.stringify(previous) !== JSON.stringify(next)) {
        publishState(
          Object.freeze({
            status: "loading",
            mode: "bearer",
            reason: "identity-transition",
          }),
        );
        await configuration.identityLifecycle.transition({
          reason:
            next.status === "anonymous" && previous.status === "authenticated"
              ? "session-expired"
              : "principal-change",
          previous,
          next,
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
      }
      abortIfRequested(options.signal);
      publishState(next);
      return next;
    } catch (error: unknown) {
      publishState(
        Object.freeze({ status: "error", mode: "bearer", reason: "bootstrap-failed" }),
      );
      notifyDiagnostic(configuration.onDiagnostic, {
        mode: "bearer",
        event: "bootstrap-failed",
        audience,
        category: options.signal?.aborted === true ? "aborted" : "provider",
      });
      throw error;
    }
  };

  const runLogout = async (
    operation: (request: BearerTokenRequest) => Promise<void>,
    reason: "logout" | "logout-all",
    options: GetSessionOptions,
  ): Promise<void> => {
    const previous = state;
    publishState(
      Object.freeze({
        status: "loading",
        mode: "bearer",
        reason: "identity-transition",
      }),
    );
    let backendChanged = false;
    try {
      abortIfRequested(options.signal);
      await operation(tokenRequest(options.signal));
      backendChanged = true;
      await configuration.tokens.clearAccessToken(tokenRequest(options.signal));
      cachedToken = null;
      const next: AuthSessionState = Object.freeze({
        status: "anonymous",
        mode: "bearer",
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
    } catch (error: unknown) {
      publishState(
        backendChanged
          ? Object.freeze({
              status: "error",
              mode: "bearer",
              reason: "identity-transition-failed",
            })
          : previous,
      );
      throw error;
    }
  };

  return Object.freeze({
    mode: "bearer" as const,
    audience,
    requestCredentials: "omit" as const,
    authorize,
    getSnapshot(): AuthSessionState {
      return state;
    },
    getSession,
    subscribe(listener: AuthSessionListener): () => void {
      if (disposed) {
        throw new Error("The bearer authentication manager is disposed.");
      }
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    async executeAuthorized<TValue>(
      context: AuthRequestContext,
      operation: BearerAuthorizedOperation<TValue>,
    ): Promise<TValue> {
      const firstAuthorization = await authorize(context);
      try {
        return await operation(firstAuthorization, 0, context.signal);
      } catch (error: unknown) {
        if (!isUnauthorized(error)) {
          throw error;
        }
        notifyDiagnostic(configuration.onDiagnostic, {
          mode: "bearer",
          event: "unauthorized-retry",
          audience,
          category: "unauthorized",
        });
        const refreshed = await getUsableToken(context.signal, true);
        if (refreshed === null) {
          throw error;
        }
        return operation(authorizationForToken(refreshed), 1, context.signal);
      }
    },
    async logout(options: GetSessionOptions = {}): Promise<void> {
      await runLogout((request) => configuration.lifecycle.revoke(request), "logout", options);
    },
    async logoutAll(options: GetSessionOptions = {}): Promise<void> {
      await runLogout(
        (request) => configuration.lifecycle.revokeAll(request),
        "logout-all",
        options,
      );
    },
    getDiagnostics(): Readonly<BearerDiagnostics> {
      let tokenState: BearerDiagnostics["tokenState"] = "unavailable";
      if (cachedToken !== undefined && cachedToken !== null) {
        const remainingMs = cachedToken.expiresAt - now();
        tokenState =
          remainingMs <= 0
            ? "expired"
            : remainingMs <= minimumValidityMs
              ? "expiring"
              : "available";
      }
      return Object.freeze({
        mode: "bearer",
        audience,
        tokenState,
        refreshInFlight: refreshFlight !== undefined,
      });
    },
    dispose(): void {
      if (disposed) {
        return;
      }
      disposed = true;
      refreshFlight?.controller.abort(new DOMException("Auth manager disposed", "AbortError"));
      listeners.clear();
      cachedToken = null;
    },
  });
}
