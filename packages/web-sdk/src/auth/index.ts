import { createBearerAuthManager } from "./bearer.js";
import type {
  BearerAuthManager,
  BearerAuthManagerConfiguration,
} from "./bearer.js";
import { createNoAuthManager } from "./none.js";
import { createOidcRedirectAuthManager } from "./oidc.js";
import type {
  OidcRedirectAuthManager,
  OidcRedirectAuthManagerConfiguration,
} from "./oidc.js";
import { createSessionAuthManager } from "./session.js";
import type {
  SessionAuthManager,
  SessionAuthManagerConfiguration,
} from "./session.js";
import type { AuthManager } from "./types.js";

export {
  AUTH_MODES,
  isAuthMode,
  isAuthenticated,
} from "./types.js";
export type {
  AnonymousSession,
  AuthAdapter,
  AuthDiagnostic,
  AuthDiagnosticListener,
  AuthIdentity,
  AuthManager,
  AuthMode,
  AuthRequestAuthorization,
  AuthRequestContext,
  AuthSessionListener,
  AuthSessionState,
  AuthenticatedSession,
  AuthenticatedState,
  CurrentPrincipalFailure,
  CurrentPrincipalPayload,
  CurrentPrincipalPort,
  CurrentPrincipalResult,
  CurrentPrincipalSuccess,
  CurrentPrincipalUnauthenticated,
  FailedSession,
  GetSessionOptions,
  IdentityTransitionContext,
  IdentityTransitionLifecycle,
  IdentityTransitionReason,
  LoadingSession,
  PublicPrincipal,
  PublicSessionMetadata,
  TenantContext,
} from "./types.js";

export {
  AuthIdentityTransitionError,
  CurrentPrincipalRequestError,
  createSessionAuthManager,
  normalizeCurrentPrincipalResult,
} from "./session.js";
export type {
  CrossTabAuthSignal,
  CrossTabAuthSignalPort,
  CrossTabAuthSignalReason,
  SessionAuthManager,
  SessionAuthManagerConfiguration,
  SessionCsrfPort,
  SessionLifecyclePort,
  SessionOperationOptions,
} from "./session.js";

export {
  BearerUnauthorizedError,
  createBearerAuthManager,
} from "./bearer.js";
export type {
  BearerAuthManager,
  BearerAuthManagerConfiguration,
  BearerAuthorizedOperation,
  BearerDiagnostics,
  BearerLifecyclePort,
  BearerTokenProvider,
  BearerTokenRequest,
  BearerTokenResult,
} from "./bearer.js";

export { createOidcRedirectAuthManager } from "./oidc.js";
export type {
  LinkedIdentity,
  OidcBackendPort,
  OidcBeginLoginInput,
  OidcBeginLoginResult,
  OidcRedirectAuthManager,
  OidcRedirectAuthManagerConfiguration,
  OidcSessionLifecyclePort,
} from "./oidc.js";

export {
  createRoutePrerequisites,
  validateAppRelativeLocation,
} from "./routes.js";
export type {
  AppLocationPolicy,
  ApprovedAppLocation,
  RoutePrerequisiteConfiguration,
  RoutePrerequisiteContext,
  RoutePrerequisiteResult,
  RoutePrerequisites,
} from "./routes.js";

export { createGeneratedCurrentPrincipalPort } from "./generated-principal.js";
export { createNoAuthManager } from "./none.js";

export interface NoAuthManagerConfiguration {
  readonly mode: "none";
}

export type AuthManagerConfiguration =
  | ({ readonly mode: "session" } & SessionAuthManagerConfiguration)
  | ({ readonly mode: "bearer" } & BearerAuthManagerConfiguration)
  | ({ readonly mode: "oidc-redirect" } & OidcRedirectAuthManagerConfiguration)
  | NoAuthManagerConfiguration;

/** Creates the explicitly declared auth mode. No mode or backend lifecycle is inferred. */
export function createAuthManager(
  configuration: { readonly mode: "session" } & SessionAuthManagerConfiguration,
): SessionAuthManager;
export function createAuthManager(
  configuration: { readonly mode: "bearer" } & BearerAuthManagerConfiguration,
): BearerAuthManager;
export function createAuthManager(
  configuration: { readonly mode: "oidc-redirect" } & OidcRedirectAuthManagerConfiguration,
): OidcRedirectAuthManager;
export function createAuthManager(
  configuration: NoAuthManagerConfiguration,
): AuthManager & { readonly mode: "none" };
export function createAuthManager(configuration: AuthManagerConfiguration): AuthManager {
  switch (configuration.mode) {
    case "session": {
      const { mode: _mode, ...options } = configuration;
      return createSessionAuthManager(options);
    }
    case "bearer": {
      const { mode: _mode, ...options } = configuration;
      return createBearerAuthManager(options);
    }
    case "oidc-redirect": {
      const { mode: _mode, ...options } = configuration;
      return createOidcRedirectAuthManager(options);
    }
    case "none":
      return createNoAuthManager();
  }
}
