import { normalizePublicBasePath } from "@omnius/web-sdk/client";
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

const routeTree = rootRoute.addChildren([statusRoute]);

export function createAppRouter(
  history: RouterHistory = createBrowserHistory(),
  publicBaseValue = "/",
) {
  return createRouter({
    routeTree,
    history,
    basepath: normalizePublicBasePath(publicBaseValue),
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
