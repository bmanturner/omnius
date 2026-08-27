/** Authentication modes advertised by the canonical capability contract. */
export const AUTH_MODES = ["session", "bearer", "oidc-redirect"] as const;

export type AuthMode = (typeof AUTH_MODES)[number];

export interface AuthRequestContext {
  readonly url: URL;
  readonly method: string;
  readonly signal?: AbortSignal;
}

export interface AuthRequestAuthorization {
  readonly headers: Readonly<Record<string, string>>;
}

/** Supplies request authorization without coupling the client core to token storage. */
export interface AuthAdapter {
  readonly mode: AuthMode;
  authorize(
    context: AuthRequestContext,
  ): AuthRequestAuthorization | Promise<AuthRequestAuthorization>;
}

export interface AuthIdentity {
  readonly subject: string;
  readonly displayName?: string;
}

export type AuthState<TIdentity extends AuthIdentity = AuthIdentity> =
  | { readonly status: "anonymous" }
  | {
      readonly status: "authenticated";
      readonly mode: AuthMode;
      readonly identity: TIdentity;
    };

export type AuthenticatedState<TIdentity extends AuthIdentity = AuthIdentity> = Extract<
  AuthState<TIdentity>,
  { readonly status: "authenticated" }
>;

export function isAuthMode(value: string): value is AuthMode {
  return value === "session" || value === "bearer" || value === "oidc-redirect";
}

export function isAuthenticated<TIdentity extends AuthIdentity>(
  state: AuthState<TIdentity>,
): state is AuthenticatedState<TIdentity> {
  return state.status === "authenticated";
}
