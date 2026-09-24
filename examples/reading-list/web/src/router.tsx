import { normalizePublicBasePath } from "@omnius/web-sdk/client";
import {
  createBrowserHistory,
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
  useSearch,
} from "@tanstack/react-router";
import type { Router, RouterHistory } from "@tanstack/react-router";

import { AppShell } from "./components/app-shell";
import { ProblemState } from "./components/request-states";
import { NotFoundRoute } from "./routes/not-found-route";
import {
  AnonymousRouteGate,
  AuthenticatedRouteGate,
  validateReturnTo,
} from "./routes/route-auth-gate";

export interface LoginSearch {
  readonly returnTo?: string;
}

function parseLoginSearch(search: Readonly<Record<string, unknown>>): LoginSearch {
  const returnTo = search.returnTo;
  return typeof returnTo === "string" && returnTo.length > 0 && returnTo.length <= 2_048
    ? { returnTo }
    : {};
}

const rootRoute = createRootRoute({
  component: AppShell,
  notFoundComponent: NotFoundRoute,
  errorComponent: ({ error }) => <ProblemState error={error} />,
});

const ReadingListRoute = lazyRouteComponent(
  () => import("./routes/reading-list-route"),
  "ReadingListRoute",
);
const LoginRoute = lazyRouteComponent(() => import("./routes/login-route"), "LoginRoute");
const RegisterRoute = lazyRouteComponent(() => import("./routes/register-route"), "RegisterRoute");
const VerifyEmailRoute = lazyRouteComponent(() => import("./routes/verify-email-route"), "VerifyEmailRoute");
const ForgotPasswordRoute = lazyRouteComponent(() => import("./routes/forgot-password-route"), "ForgotPasswordRoute");
const ResetPasswordRoute = lazyRouteComponent(() => import("./routes/reset-password-route"), "ResetPasswordRoute");

function LoginRouteGate() {
  const search = useSearch({ from: "/login" });
  return (
    <AnonymousRouteGate authenticatedHome={validateReturnTo(search.returnTo)}>
      <LoginRoute />
    </AnonymousRouteGate>
  );
}

const readingListRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: () => <AuthenticatedRouteGate><ReadingListRoute /></AuthenticatedRouteGate>,
});
const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  validateSearch: parseLoginSearch,
  component: LoginRouteGate,
});
const registerRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/register",
  component: () => <AnonymousRouteGate><RegisterRoute /></AnonymousRouteGate>,
});
const verifyEmailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/verify-email",
  component: VerifyEmailRoute,
});
const forgotPasswordRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/forgot-password",
  component: () => <AnonymousRouteGate><ForgotPasswordRoute /></AnonymousRouteGate>,
});
const resetPasswordRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/reset-password",
  component: ResetPasswordRoute,
});

const routeTree = rootRoute.addChildren([
  readingListRoute,
  loginRoute,
  registerRoute,
  verifyEmailRoute,
  forgotPasswordRoute,
  resetPasswordRoute,
]);

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
