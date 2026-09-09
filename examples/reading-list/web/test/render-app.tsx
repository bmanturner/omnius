import { createServiceQueryClient, serviceQueries } from "@omnius/web-sdk/react";
import { createMemoryHistory } from "@tanstack/react-router";
import type { QueryClient } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { RenderOptions } from "@testing-library/react";

import { App } from "../src/app";

export function createTestQueryClient(): QueryClient {
  return createServiceQueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
}

export function renderApp(
  route = "/",
  options: {
    readonly queryClient?: QueryClient;
    readonly wrapper?: RenderOptions["wrapper"];
  } = {},
) {
  const history = createMemoryHistory({ initialEntries: [route] });
  const queryClient = options.queryClient ?? createTestQueryClient();
  const result = render(
    <App history={history} queryClient={queryClient} />,
    options.wrapper === undefined ? undefined : { wrapper: options.wrapper },
  );
  return { ...result, history, queryClient };
}

export function readingItemsQueryKey(): readonly unknown[] {
  return serviceQueries.getListReadingItemsQueryKey();
}
