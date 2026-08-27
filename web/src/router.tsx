import {
  createBrowserHistory,
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
} from "@tanstack/react-router";
import type { Router, RouterHistory } from "@tanstack/react-router";

import { AppShell } from "./components/app-shell";
import { ProblemState } from "./components/request-states";
import { NotFoundRoute } from "./routes/not-found-route";

export interface ReferenceRecordSearch {
  readonly limit: 10 | 25 | 50 | 100;
  readonly cursor?: string;
}

const allowedPageSizes: Readonly<Record<number, true>> = {
  10: true,
  25: true,
  50: true,
  100: true,
};

export function parseReferenceRecordSearch(
  search: Readonly<Record<string, unknown>>,
): ReferenceRecordSearch {
  const numericLimit = typeof search.limit === "string" ? Number(search.limit) : search.limit;
  const limit =
    typeof numericLimit === "number" && allowedPageSizes[numericLimit] === true
      ? (numericLimit as ReferenceRecordSearch["limit"])
      : 25;
  const cursor = search.cursor;
  return {
    limit,
    ...(typeof cursor === "string" && cursor.length > 0 && cursor.length <= 256
      ? { cursor }
      : {}),
  };
}

const rootRoute = createRootRoute({
  component: AppShell,
  notFoundComponent: NotFoundRoute,
  errorComponent: ({ error }) => <ProblemState error={error} />,
});

const statusRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: lazyRouteComponent(() => import("./routes/status-route"), "StatusRoute"),
});

export const referenceRecordsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/reference-records",
  validateSearch: parseReferenceRecordSearch,
  component: lazyRouteComponent(
    () => import("./routes/reference-records-route"),
    "ReferenceRecordsRoute",
  ),
});

const routeTree = rootRoute.addChildren([statusRoute, referenceRecordsRoute]);

export function createAppRouter(history: RouterHistory = createBrowserHistory()) {
  return createRouter({
    routeTree,
    history,
    defaultPreload: "intent",
    defaultPreloadStaleTime: 0,
    scrollRestoration: true,
  });
}
export type AppRouter = Router<typeof routeTree>;

declare module "@tanstack/react-router" {
  interface Register {
    router: AppRouter;
  }
}
