/** Authentication modes declared by an application capability manifest. */
export const AUTH_MODES = ["session", "bearer", "oidc-redirect", "none"] as const;

export type AuthMode = (typeof AUTH_MODES)[number];

export interface AuthRequestContext {
  readonly url: URL;
  readonly method: string;
  readonly signal?: AbortSignal;
}

export interface AuthRequestAuthorization {
  readonly headers: Readonly<Record<string, string>>;
}

/** Supplies request authorization without coupling transport to credential persistence. */
export interface AuthAdapter {
  readonly mode: AuthMode;
  authorize(
    context: AuthRequestContext,
  ): AuthRequestAuthorization | Promise<AuthRequestAuthorization>;
}

export function isAuthMode(value: string): value is AuthMode {
  return (AUTH_MODES as readonly string[]).includes(value);
}
