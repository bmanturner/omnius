import type {
  AuthManager,
  AuthenticatedSession,
} from "./types.js";
import {
  createSessionModeAuthManager,
} from "./session.js";
import type {
  SessionAuthManagerConfiguration,
  SessionLifecyclePort,
  SessionOperationOptions,
} from "./session.js";
import {
  validateAppRelativeLocation,
} from "./routes.js";
import type {
  AppLocationPolicy,
  ApprovedAppLocation,
} from "./routes.js";

export interface OidcBeginLoginInput {
  readonly provider: string;
  readonly returnTo: ApprovedAppLocation;
  readonly signal?: AbortSignal;
}

export interface OidcBeginLoginResult {
  readonly redirectTo: string;
}

export interface LinkedIdentity {
  readonly id: string;
  readonly provider: string;
  readonly providerSubject?: string;
  readonly displayName?: string;
}

export interface OidcBackendPort<TCallbackInput = unknown> {
  beginLogin(input: OidcBeginLoginInput): Promise<OidcBeginLoginResult>;
  completeCallback(
    input: TCallbackInput,
    options?: SessionOperationOptions,
  ): Promise<void>;
  listLinkedIdentities(options?: SessionOperationOptions): Promise<readonly LinkedIdentity[]>;
  unlinkIdentity(identityId: string, options?: SessionOperationOptions): Promise<void>;
}

export type OidcSessionLifecyclePort<TElevationInput = unknown> = Omit<
  SessionLifecyclePort<never, TElevationInput>,
  "login"
>;

export interface OidcRedirectAuthManager<
  TCallbackInput = unknown,
  TElevationInput = unknown,
> extends AuthManager {
  readonly mode: "oidc-redirect";
  beginOidcLogin(
    provider: string,
    returnTo: string,
    options?: SessionOperationOptions,
  ): Promise<OidcBeginLoginResult>;
  completeOidcCallback(
    input: TCallbackInput,
    options?: SessionOperationOptions,
  ): Promise<AuthenticatedSession>;
  listLinkedIdentities(options?: SessionOperationOptions): Promise<readonly LinkedIdentity[]>;
  unlinkIdentity(identityId: string, options?: SessionOperationOptions): Promise<void>;
  elevate(
    input: TElevationInput,
    options?: SessionOperationOptions,
  ): Promise<AuthenticatedSession>;
  logout(options?: SessionOperationOptions): Promise<void>;
  logoutAll(options?: SessionOperationOptions): Promise<void>;
}

export interface OidcRedirectAuthManagerConfiguration<
  TCallbackInput = unknown,
  TElevationInput = unknown,
> extends Omit<
    SessionAuthManagerConfiguration<never, TElevationInput>,
    "lifecycle"
  > {
  readonly lifecycle: OidcSessionLifecyclePort<TElevationInput>;
  readonly oidc: OidcBackendPort<TCallbackInput>;
  readonly returnLocations: AppLocationPolicy;
}

function validateProvider(provider: string): string {
  if (
    provider.length === 0 ||
    provider.length > 128 ||
    provider.trim() !== provider ||
    !/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/u.test(provider)
  ) {
    throw new TypeError("OIDC provider must be a valid configured provider identifier.");
  }
  return provider;
}

function validateOidcRedirect(result: OidcBeginLoginResult): OidcBeginLoginResult {
  let parsed: URL;
  try {
    parsed = new URL(result.redirectTo);
  } catch (error: unknown) {
    throw new TypeError("The OIDC backend returned an invalid authorization redirect.", {
      cause: error,
    });
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.username.length > 0 ||
    parsed.password.length > 0
  ) {
    throw new TypeError("The OIDC backend returned an unsafe authorization redirect.");
  }
  return Object.freeze({ redirectTo: parsed.href });
}

function normalizeLinkedIdentities(
  identities: readonly LinkedIdentity[],
): readonly LinkedIdentity[] {
  return Object.freeze(
    identities.map((identity) => {
      if (
        identity.id.length === 0 ||
        identity.id.trim() !== identity.id ||
        identity.provider.length === 0 ||
        identity.provider.trim() !== identity.provider
      ) {
        throw new TypeError("The OIDC backend returned a malformed linked identity.");
      }
      return Object.freeze({ ...identity });
    }),
  );
}

export function createOidcRedirectAuthManager<
  TCallbackInput = unknown,
  TElevationInput = unknown,
>(
  configuration: OidcRedirectAuthManagerConfiguration<TCallbackInput, TElevationInput>,
): OidcRedirectAuthManager<TCallbackInput, TElevationInput> {
  const sessionLifecycle: SessionLifecyclePort<TCallbackInput, TElevationInput> = {
    login: (input, options) => configuration.oidc.completeCallback(input, options),
    elevate: (input, options) => configuration.lifecycle.elevate(input, options),
    logout: (options) => configuration.lifecycle.logout(options),
    logoutAll: (options) => configuration.lifecycle.logoutAll(options),
  };
  const sessionManager = createSessionModeAuthManager(
    {
      ...configuration,
      lifecycle: sessionLifecycle,
    },
    "oidc-redirect",
  );

  return Object.freeze({
    mode: "oidc-redirect" as const,
    requestCredentials: sessionManager.requestCredentials,
    authorize: sessionManager.authorize,
    getSnapshot: sessionManager.getSnapshot,
    getSession: sessionManager.getSession,
    subscribe: sessionManager.subscribe,
    elevate: sessionManager.elevate,
    logout: sessionManager.logout,
    logoutAll: sessionManager.logoutAll,
    dispose: sessionManager.dispose,
    async beginOidcLogin(
      provider: string,
      returnTo: string,
      options: SessionOperationOptions = {},
    ): Promise<OidcBeginLoginResult> {
      const approvedReturnTo = validateAppRelativeLocation(
        returnTo,
        configuration.returnLocations,
      );
      const result = await configuration.oidc.beginLogin({
        provider: validateProvider(provider),
        returnTo: approvedReturnTo,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      return validateOidcRedirect(result);
    },
    async completeOidcCallback(
      input: TCallbackInput,
      options: SessionOperationOptions = {},
    ): Promise<AuthenticatedSession> {
      return sessionManager.login(input, options);
    },
    async listLinkedIdentities(
      options: SessionOperationOptions = {},
    ): Promise<readonly LinkedIdentity[]> {
      return normalizeLinkedIdentities(
        await configuration.oidc.listLinkedIdentities(options),
      );
    },
    async unlinkIdentity(
      identityId: string,
      options: SessionOperationOptions = {},
    ): Promise<void> {
      if (identityId.length === 0 || identityId.trim() !== identityId) {
        throw new TypeError("Linked identity ID must be a non-empty trimmed value.");
      }
      await configuration.oidc.unlinkIdentity(identityId, options);
      await sessionManager.getSession(options);
    },
  });
}
