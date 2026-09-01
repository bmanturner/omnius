import {
  createVerifiedCapabilityRegistry,
  type CapabilityRegistry,
} from "@omnius/web-sdk/capabilities";
import {
  createServiceClient,
  normalizePublicBasePath,
  type DefinedServiceClientConfiguration,
} from "@omnius/web-sdk/client";
import {
  RealtimeProvider,
  WebSdkProvider,
  createServiceQueryClient,
} from "@omnius/web-sdk/react";
import {
  createRealtimeManager,
  createSseTransport,
  createWebSocketTransport,
  type RealtimeManager,
} from "@omnius/web-sdk/realtime";
import type { QueryClient } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import type { RouterHistory } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";

import capabilityManifestAssetUrl from "../../contracts/capabilities.json?url";
import {
  createBrowserSessionAuthManager,
  type BrowserSessionAuthManager,
} from "./auth-manager";
import { BUILD_METADATA } from "./build-metadata";
import { LoadingState, ProblemState } from "./components/request-states";
import { createAppRouter, type AppRouter } from "./router";
import {
  WebRuntimeCompositionProvider,
  type WebApplicationContributions,
} from "./runtime-composition";

const DEFAULT_PUBLIC_BASE_PATH = normalizePublicBasePath(import.meta.env.BASE_URL);
const DEFAULT_SERVICE_CONFIGURATION: Readonly<DefinedServiceClientConfiguration> =
  Object.freeze({
    baseUrl: "/",
    credentials: "same-origin",
  });
const EMPTY_CONTRIBUTIONS: Readonly<WebApplicationContributions> = Object.freeze({});

interface AppFoundation {
  readonly queryClient: QueryClient;
  readonly router: AppRouter;
}

interface AppComposition extends AppFoundation {
  readonly authManager: BrowserSessionAuthManager | null;
  readonly capabilityRegistry: CapabilityRegistry;
  readonly realtimeManager: RealtimeManager | null;
}

type BootstrapState =
  | { readonly status: "loading" }
  | { readonly status: "ready"; readonly composition: AppComposition }
  | { readonly status: "error"; readonly error: unknown };

export interface AppProps {
  readonly capabilityManifestUrl?: string;
  readonly configuration?: Readonly<DefinedServiceClientConfiguration>;
  readonly contributions?: Readonly<WebApplicationContributions>;
  readonly history?: RouterHistory;
  readonly queryClient?: QueryClient;
  readonly publicBasePath?: string;
}

function capabilityAvailable(registry: CapabilityRegistry, capabilityId: string): boolean {
  return (
    registry.resolveCompiled(capabilityId).compiled &&
    registry.resolveRuntimeAvailability(capabilityId).available
  );
}

function realtimeFromCapabilities(
  registry: CapabilityRegistry,
  configuration: Readonly<DefinedServiceClientConfiguration>,
): RealtimeManager | null {
  if (!capabilityAvailable(registry, "web-realtime")) return null;
  const { sse, websocket } = registry.manifest.transports;
  if (sse === undefined && websocket === undefined) {
    throw new Error("The runtime advertises web-realtime without a concrete transport.");
  }
  const idFactory = (): string => globalThis.crypto.randomUUID();
  const transport =
    websocket === undefined
      ? createSseTransport({ url: sse as string, baseUrl: configuration.baseUrl })
      : createWebSocketTransport({
          idFactory,
          url: websocket,
          baseUrl: configuration.baseUrl,
        });
  return createRealtimeManager({ idFactory, transport });
}

async function fetchCapabilityManifest(url: string, signal: AbortSignal): Promise<unknown> {
  const response = await fetch(url, {
    signal,
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`Capability manifest request failed with status ${String(response.status)}.`);
  }
  return response.json();
}

export function App({
  capabilityManifestUrl = capabilityManifestAssetUrl,
  configuration,
  contributions = EMPTY_CONTRIBUTIONS,
  history,
  publicBasePath: publicBaseValue = DEFAULT_PUBLIC_BASE_PATH,
  queryClient,
}: AppProps) {
  const publicBasePath = normalizePublicBasePath(publicBaseValue);
  const clientConfiguration = configuration ?? DEFAULT_SERVICE_CONFIGURATION;
  const foundation = useMemo<AppFoundation>(() => {
    const activeQueryClient = queryClient ?? createServiceQueryClient();
    return {
      queryClient: activeQueryClient,
      router: createAppRouter(history, publicBasePath),
    };
  }, [history, publicBasePath, queryClient]);
  const [bootstrap, setBootstrap] = useState<BootstrapState>({ status: "loading" });

  useEffect(() => {
    const abort = new AbortController();
    let acquired: AppComposition | undefined;
    setBootstrap({ status: "loading" });
    const metadataClient = createServiceClient(clientConfiguration);
    void Promise.all([
      fetchCapabilityManifest(capabilityManifestUrl, abort.signal),
      metadataClient.request<unknown>("/api/_meta", { signal: abort.signal }),
    ])
      .then(([manifest, runtimeResponse]) => {
        if (abort.signal.aborted) return;
        const capabilityRegistry = createVerifiedCapabilityRegistry(
          manifest,
          runtimeResponse.data,
          { expectedContractHash: BUILD_METADATA.contractHash },
        );
        const realtimeManager = realtimeFromCapabilities(capabilityRegistry, clientConfiguration);
        const authManager = capabilityAvailable(capabilityRegistry, "web-auth")
          ? createBrowserSessionAuthManager(
              clientConfiguration,
              foundation.queryClient,
              realtimeManager ?? undefined,
            )
          : null;
        acquired = {
          ...foundation,
          authManager,
          capabilityRegistry,
          realtimeManager,
        };
        setBootstrap({ status: "ready", composition: acquired });
      })
      .catch((error: unknown) => {
        if (!abort.signal.aborted) setBootstrap({ status: "error", error });
      });
    return () => {
      abort.abort();
      acquired?.authManager?.dispose();
      acquired?.realtimeManager?.dispose();
    };
  }, [capabilityManifestUrl, clientConfiguration, foundation]);

  if (bootstrap.status === "loading") {
    return <LoadingState label="Verifying service capabilities" />;
  }
  if (bootstrap.status === "error") {
    return <ProblemState error={bootstrap.error} />;
  }

  const { composition } = bootstrap;
  const router = <RouterProvider router={composition.router} />;
  const routedApplication =
    composition.realtimeManager === null ? (
      router
    ) : (
      <RealtimeProvider manager={composition.realtimeManager}>{router}</RealtimeProvider>
    );
  return (
    <WebSdkProvider
      authManager={composition.authManager ?? undefined}
      capabilityRegistry={composition.capabilityRegistry}
      configuration={clientConfiguration}
      queryClient={composition.queryClient}
    >
      <WebRuntimeCompositionProvider
        contributions={contributions}
        realtimeManager={composition.realtimeManager}
      >
        {routedApplication}
      </WebRuntimeCompositionProvider>
    </WebSdkProvider>
  );
}
