import type {
  AuthManager,
  AuthRequestAuthorization,
  AuthSessionListener,
  AuthSessionState,
} from "./types.js";

const NONE_SESSION: AuthSessionState = Object.freeze({
  status: "anonymous",
  mode: "none",
  reason: "none",
});

const EMPTY_AUTHORIZATION: AuthRequestAuthorization = Object.freeze({
  headers: Object.freeze({}),
});

/** Creates an explicitly unauthenticated manager that never sends ambient credentials. */
export function createNoAuthManager(): AuthManager & { readonly mode: "none" } {
  return Object.freeze({
    mode: "none" as const,
    requestCredentials: "omit" as const,
    authorize(): AuthRequestAuthorization {
      return EMPTY_AUTHORIZATION;
    },
    getSnapshot(): AuthSessionState {
      return NONE_SESSION;
    },
    async getSession(): Promise<AuthSessionState> {
      return NONE_SESSION;
    },
    subscribe(_listener: AuthSessionListener): () => void {
      return () => undefined;
    },
    dispose(): void {
      // No resources are owned in explicit unauthenticated mode.
    },
  });
}
