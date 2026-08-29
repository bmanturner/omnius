import {
  normalizePublicBasePath,
  type DefinedServiceClientConfiguration,
} from "@omnius/web-sdk/client";
import { WebSdkProvider, createServiceQueryClient } from "@omnius/web-sdk/react";
import type { QueryClient } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import type { RouterHistory } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import {
  createBrowserSessionAuthManager,
  type BrowserSessionAuthManager,
} from "./auth-manager";
import { createAppRouter } from "./router";
import type { AppRouter } from "./router";

const DEFAULT_PUBLIC_BASE_PATH = normalizePublicBasePath(import.meta.env.BASE_URL);
const DEFAULT_SERVICE_CONFIGURATION: Readonly<DefinedServiceClientConfiguration> =
  Object.freeze({
    baseUrl: "/",
    credentials: "same-origin",
  });

interface AppComposition {
  readonly authManager: BrowserSessionAuthManager;
  readonly queryClient: QueryClient;
  readonly router: AppRouter;
}

export interface AppProps {
  readonly configuration?: Readonly<DefinedServiceClientConfiguration>;
  readonly history?: RouterHistory;
  readonly queryClient?: QueryClient;
  readonly publicBasePath?: string;
}

export function App({
  configuration,
  history,
  publicBasePath: publicBaseValue = DEFAULT_PUBLIC_BASE_PATH,
  queryClient,
}: AppProps) {
  const publicBasePath = normalizePublicBasePath(publicBaseValue);
  const clientConfiguration = configuration ?? DEFAULT_SERVICE_CONFIGURATION;
  const [composition] = useState<AppComposition>(() => {
    const activeQueryClient = queryClient ?? createServiceQueryClient();
    return {
      authManager: createBrowserSessionAuthManager(clientConfiguration, activeQueryClient),
      queryClient: activeQueryClient,
      router: createAppRouter(history, publicBasePath),
    };
  });
  useEffect(() => () => composition.authManager.dispose(), [composition.authManager]);
  return (
    <WebSdkProvider
      authManager={composition.authManager}
      configuration={clientConfiguration}
      queryClient={composition.queryClient}
    >
      <RouterProvider router={composition.router} />
    </WebSdkProvider>
  );
}
