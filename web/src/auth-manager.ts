import {
  createGeneratedCurrentPrincipalPort,
  createSessionAuthManager,
  type CrossTabAuthSignalPort,
  type IdentityTransitionLifecycle,
  type SessionAuthManager,
  type SessionOperationOptions,
} from "@omnius/web-sdk/auth";
import {
  createServiceClient,
  serviceHttp,
  type DefinedServiceClientConfiguration,
} from "@omnius/web-sdk/client";
import { createQueryIdentityTransitionLifecycle } from "@omnius/web-sdk/react";
import type { QueryClient } from "@tanstack/react-query";

export interface LoginCredentials {
  readonly identifier: string;
  readonly password: string;
}

export type BrowserSessionAuthManager = SessionAuthManager<LoginCredentials, never>;

function createCrossTabPort(): CrossTabAuthSignalPort {
  if (typeof BroadcastChannel === "undefined") {
    const listeners = new Set<(value: unknown) => void>();
    return Object.freeze({
      publish(value: unknown): void {
        for (const listener of listeners) listener(value);
      },
      subscribe(listener: (value: unknown) => void): () => void {
        listeners.add(listener);
        return () => listeners.delete(listener);
      },
      close(): void {
        listeners.clear();
      },
    });
  }

  const channel = new BroadcastChannel("omnius-auth-session");
  return Object.freeze({
    publish(value: unknown): void {
      channel.postMessage(value);
    },
    subscribe(listener: (value: unknown) => void): () => void {
      const receive = (event: MessageEvent<unknown>): void => listener(event.data);
      channel.addEventListener("message", receive);
      return () => channel.removeEventListener("message", receive);
    },
    close(): void {
      channel.close();
    },
  });
}

export function createBrowserSessionAuthManager(
  configuration: Readonly<DefinedServiceClientConfiguration>,
  queryClient: QueryClient,
): BrowserSessionAuthManager {
  const { auth: _ignoredAuth, ...clientConfiguration } = configuration;
  const client = createServiceClient(clientConfiguration);
  const requestOptions = (signal?: AbortSignal): Parameters<typeof serviceHttp.loginBrowserSession>[1] =>
    client.requestOptions(signal === undefined ? {} : { signal });
  const identityLifecycle: IdentityTransitionLifecycle = createQueryIdentityTransitionLifecycle({
    queryClient,
    realtime: Object.freeze({
      async resetForIdentityTransition(): Promise<void> {},
    }),
  });

  return createSessionAuthManager<LoginCredentials, never>({
    principal: createGeneratedCurrentPrincipalPort(client),
    lifecycle: Object.freeze({
      async login(input: LoginCredentials, options?: SessionOperationOptions): Promise<void> {
        await serviceHttp.loginBrowserSession(input, requestOptions(options?.signal));
      },
      async elevate(): Promise<void> {
        throw new TypeError("Password sessions do not expose a separate elevation operation.");
      },
      async logout(options?: SessionOperationOptions): Promise<void> {
        await serviceHttp.logoutBrowserSession(requestOptions(options?.signal));
      },
      async logoutAll(options?: SessionOperationOptions): Promise<void> {
        await serviceHttp.logoutAllBrowserSessions(requestOptions(options?.signal));
      },
    }),
    identityLifecycle,
    crossTab: createCrossTabPort(),
    trustedOrigin: globalThis.location.origin,
    credentials: configuration.credentials ?? "same-origin",
  });
}
