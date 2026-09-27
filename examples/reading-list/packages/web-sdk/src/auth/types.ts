import type {
  AuthAdapter,
  AuthMode,
  AuthRequestAuthorization,
  AuthRequestContext,
} from "../client/auth.js";
import type { PresentationAuthorizationSnapshot } from "../authorization/index.js";

export { AUTH_MODES, isAuthMode } from "../client/auth.js";
export type {
  AuthAdapter,
  AuthMode,
  AuthRequestAuthorization,
  AuthRequestContext,
} from "../client/auth.js";

export interface AuthIdentity {
  readonly subject: string;
  readonly displayName?: string;
}

/** Public identity data only. It must never contain a session identifier or bearer token. */
export interface PublicPrincipal extends AuthIdentity {
  readonly kind: string;
}

export interface PublicSessionMetadata {
  readonly authenticatedAt: string;
  readonly authenticationMethod: string;
  readonly assurance: string;
  readonly expiresAt?: string;
}

export interface TenantContext {
  readonly id: string;
  readonly displayName?: string;
}

export interface AuthenticatedSession {
  readonly status: "authenticated";
  readonly mode: Exclude<AuthMode, "none">;
  readonly principal: Readonly<PublicPrincipal>;
  readonly session: Readonly<PublicSessionMetadata>;
  readonly presentation: Readonly<PresentationAuthorizationSnapshot>;
  readonly scopes: readonly string[];
  readonly tenant: Readonly<TenantContext> | null;
}

export interface AnonymousSession {
  readonly status: "anonymous";
  readonly mode: AuthMode;
  readonly reason: "none" | "not-authenticated" | "expired-or-revoked" | "logged-out";
  readonly problemCode?: string;
}

export interface LoadingSession {
  readonly status: "loading";
  readonly mode: AuthMode;
  readonly reason: "initial" | "identity-transition" | "cross-tab-revalidation";
}

export interface FailedSession {
  readonly status: "error";
  readonly mode: AuthMode;
  readonly reason: "bootstrap-failed" | "identity-transition-failed";
}

export type AuthSessionState =
  | LoadingSession
  | AnonymousSession
  | AuthenticatedSession
  | FailedSession;

export type AuthenticatedState = AuthenticatedSession;

export type IdentityTransitionReason =
  | "login"
  | "privilege-elevation"
  | "logout"
  | "logout-all"
  | "principal-change"
  | "permission-change"
  | "tenant-change"
  | "session-expired"
  | "cross-tab";

export interface IdentityTransitionContext {
  readonly reason: IdentityTransitionReason;
  readonly previous: AuthSessionState;
  readonly next: AuthSessionState;
  readonly signal?: AbortSignal;
}

/** Host-owned cache, local-state, and realtime cleanup boundary for identity transitions. */
export interface IdentityTransitionLifecycle {
  transition(context: IdentityTransitionContext): void | Promise<void>;
}

export type AuthSessionListener = (state: AuthSessionState) => void;

export interface GetSessionOptions {
  readonly signal?: AbortSignal;
}

export interface AuthManager extends AuthAdapter {
  readonly requestCredentials: RequestCredentials;
  getSnapshot(): AuthSessionState;
  getSession(options?: GetSessionOptions): Promise<AuthSessionState>;
  subscribe(listener: AuthSessionListener): () => void;
  dispose(): void;
}

export interface CurrentPrincipalPayload {
  readonly subject_id: string;
  readonly kind: string;
  readonly authenticated_at: string;
  readonly auth_method: string;
  readonly assurance: string;
  readonly scopes: readonly string[];
  readonly tenant_id?: string | null;
  readonly display_name?: string;
  readonly expires_at?: string;
  readonly presentation_permissions?: readonly string[];
  readonly resource_permissions?: readonly {
    readonly permission: string;
    readonly context: Readonly<Record<string, string | number | boolean | null>>;
  }[];
  readonly tenant?: {
    readonly id: string;
    readonly display_name?: string;
  } | null;
}

export interface CurrentPrincipalSuccess {
  readonly status: 200;
  readonly data: CurrentPrincipalPayload;
}

export interface CurrentPrincipalUnauthenticated {
  readonly status: 401;
  readonly data: {
    readonly code: string;
  };
}

export interface CurrentPrincipalFailure {
  readonly status: number;
  readonly data: unknown;
}

export type CurrentPrincipalResult =
  | CurrentPrincipalSuccess
  | CurrentPrincipalUnauthenticated
  | CurrentPrincipalFailure;

/** Injected operation boundary normally backed by generated `getCurrentPrincipal`. */
export interface CurrentPrincipalPort {
  getCurrentPrincipal(options?: GetSessionOptions): Promise<CurrentPrincipalResult>;
}

export interface AuthDiagnostic {
  readonly mode: AuthMode;
  readonly event:
    | "bootstrap-failed"
    | "cross-tab-revalidation-failed"
    | "token-unavailable"
    | "token-refreshed"
    | "token-refresh-failed"
    | "unauthorized-retry";
  readonly audience?: string;
  readonly category?: "aborted" | "provider" | "unauthorized" | "invalid-token";
}

export type AuthDiagnosticListener = (diagnostic: Readonly<AuthDiagnostic>) => void;



export function isAuthenticated(state: AuthSessionState): state is AuthenticatedSession {
  return state.status === "authenticated";
}
