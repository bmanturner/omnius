import type { DefinedServiceClientConfiguration } from "@omnius/web-sdk/client";
import { WebSdkProvider } from "@omnius/web-sdk/react";
import type { QueryClient } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import type { RouterHistory } from "@tanstack/react-router";
import { useState } from "react";

import { createAppRouter } from "./router";

const DEFAULT_SERVICE_CONFIGURATION: Readonly<DefinedServiceClientConfiguration> = Object.freeze({
  baseUrl: "/",
  credentials: "same-origin",
});

export interface AppProps {
  readonly configuration?: Readonly<DefinedServiceClientConfiguration>;
  readonly history?: RouterHistory;
  readonly queryClient?: QueryClient;
}

export function App({
  configuration = DEFAULT_SERVICE_CONFIGURATION,
  history,
  queryClient,
}: AppProps) {
  const [router] = useState(() => createAppRouter(history));
  return (
    <WebSdkProvider
      configuration={configuration}
      {...(queryClient === undefined ? {} : { queryClient })}
    >
      <RouterProvider router={router} />
    </WebSdkProvider>
  );
}
