import {
  normalizePublicBasePath,
  type DefinedServiceClientConfiguration,
} from "@omnius/web-sdk/client";
import { WebSdkProvider } from "@omnius/web-sdk/react";
import type { QueryClient } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import type { RouterHistory } from "@tanstack/react-router";
import { useState } from "react";
import { createAppRouter } from "./router";

const DEFAULT_PUBLIC_BASE_PATH = normalizePublicBasePath(import.meta.env.BASE_URL);
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
  configuration,
  history,
  publicBasePath: publicBaseValue = DEFAULT_PUBLIC_BASE_PATH,
  queryClient,
}: AppProps) {
  const publicBasePath = normalizePublicBasePath(publicBaseValue);
  const clientConfiguration = configuration ?? DEFAULT_SERVICE_CONFIGURATION;
  const [router] = useState(() => createAppRouter(history, publicBasePath));
  return (
    <WebSdkProvider
      configuration={clientConfiguration}
      {...(queryClient === undefined ? {} : { queryClient })}
    >
      <RouterProvider router={router} />
    </WebSdkProvider>
  );
}
