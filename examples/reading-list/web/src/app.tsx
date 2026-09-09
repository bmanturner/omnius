import type { DefinedServiceClientConfiguration } from "@omnius/web-sdk/client";
import { WebSdkProvider, createServiceQueryClient } from "@omnius/web-sdk/react";
import type { QueryClient } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import type { RouterHistory } from "@tanstack/react-router";
import { useEffect, useMemo } from "react";

import { createBrowserSessionAuthManager } from "./auth-manager";
import { createAppRouter } from "./router";

const DEFAULT_SERVICE_CONFIGURATION: Readonly<DefinedServiceClientConfiguration> =
  Object.freeze({
    baseUrl: "/",
    credentials: "same-origin",
  });

export interface AppProps {
  readonly configuration?: Readonly<DefinedServiceClientConfiguration>;
  readonly history?: RouterHistory;
  readonly queryClient?: QueryClient;
  readonly publicBasePath?: string;
}

export function App({
  configuration = DEFAULT_SERVICE_CONFIGURATION,
  history,
  publicBasePath = import.meta.env.BASE_URL,
  queryClient,
}: AppProps) {
  const activeQueryClient = useMemo(
    () => queryClient ?? createServiceQueryClient(),
    [queryClient],
  );
  const authManager = useMemo(
    () => createBrowserSessionAuthManager(configuration, activeQueryClient),
    [activeQueryClient, configuration],
  );
  const router = useMemo(
    () => createAppRouter(history, publicBasePath),
    [history, publicBasePath],
  );

  useEffect(() => () => authManager.dispose(), [authManager]);

  return (
    <WebSdkProvider
      authManager={authManager}
      configuration={configuration}
      queryClient={activeQueryClient}
    >
      <RouterProvider router={router} />
    </WebSdkProvider>
  );
}
