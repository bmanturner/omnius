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
import { AnonymousRouteGate, AuthenticatedRouteGate } from "./routes/route-auth-gate";
export interface ReferenceRecordSearch {
  readonly limit: 10 | 25 | 50 | 100;
  readonly cursor?: string;
  readonly name?: string;
}

export interface LoginSearch {
  readonly returnTo?: string;
}

export interface AuthorizeSearch {
  readonly request?: string;
}

function parseLoginSearch(search: Readonly<Record<string, unknown>>): LoginSearch {
  const returnTo = search.returnTo;
  return typeof returnTo === "string" && returnTo.length > 0 && returnTo.length <= 2_048
    ? { returnTo }
    : {};
}

function parseAuthorizeSearch(search: Readonly<Record<string, unknown>>): AuthorizeSearch {
  const request = search.request;
  return typeof request === "string" && request.length > 0 && request.length <= 256
    ? { request }
    : {};
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
  const name = typeof search.name === "string" ? search.name.trim() : "";
  let nameCodePoints = 0;
  for (const _codePoint of name) {
    nameCodePoints += 1;
  }
  return {
    limit,
    ...(typeof cursor === "string" && cursor.length > 0 && cursor.length <= 256
      ? { cursor }
      : {}),
    ...(nameCodePoints > 0 && nameCodePoints <= 100 ? { name } : {}),
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
  path: "/records",
  validateSearch: parseReferenceRecordSearch,
  component: lazyRouteComponent(
    () => import("./routes/reference-records-route"),
    "ReferenceRecordsRoute",
  ),
});

const LoginRouteComponent = lazyRouteComponent(() => import("./routes/login-route"), "LoginRoute");
const RegisterRouteComponent = lazyRouteComponent(() => import("./routes/register-route"), "RegisterRoute");
const ForgotPasswordRouteComponent = lazyRouteComponent(() => import("./routes/forgot-password-route"), "ForgotPasswordRoute");
const AccountRouteComponent = lazyRouteComponent(() => import("./routes/account-route"), "AccountRoute");
const AccountSecurityRouteComponent = lazyRouteComponent(() => import("./routes/account-security-route"), "AccountSecurityRoute");
const AccountSessionsRouteComponent = lazyRouteComponent(() => import("./routes/account-sessions-route"), "AccountSessionsRoute");
const AccountApiKeysRouteComponent = lazyRouteComponent(() => import("./routes/account-api-keys-route"), "AccountApiKeysRoute");
const AccountConnectedAppsRouteComponent = lazyRouteComponent(() => import("./routes/account-connected-apps-route"), "AccountConnectedAppsRoute");
const AuthorizeRouteComponent = lazyRouteComponent(() => import("./routes/authorize-route"), "AuthorizeRoute");

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  validateSearch: parseLoginSearch,
  component: () => <AnonymousRouteGate><LoginRouteComponent /></AnonymousRouteGate>,
});
const registerRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/register",
  component: () => <AnonymousRouteGate><RegisterRouteComponent /></AnonymousRouteGate>,
});
const verifyEmailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/verify-email",
  component: lazyRouteComponent(() => import("./routes/verify-email-route"), "VerifyEmailRoute"),
});
const forgotPasswordRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/forgot-password",
  component: () => <AnonymousRouteGate><ForgotPasswordRouteComponent /></AnonymousRouteGate>,
});
const resetPasswordRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/reset-password",
  component: lazyRouteComponent(() => import("./routes/reset-password-route"), "ResetPasswordRoute"),
});
const authorizeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/authorize",
  validateSearch: parseAuthorizeSearch,
  component: () => <AuthenticatedRouteGate><AuthorizeRouteComponent /></AuthenticatedRouteGate>,
});
const accountRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/account",
  component: () => <AuthenticatedRouteGate><AccountRouteComponent /></AuthenticatedRouteGate>,
});
const accountSecurityRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/account/security",
  component: () => <AuthenticatedRouteGate><AccountSecurityRouteComponent /></AuthenticatedRouteGate>,
});
const accountSessionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/account/sessions",
  component: () => <AuthenticatedRouteGate><AccountSessionsRouteComponent /></AuthenticatedRouteGate>,
});
const accountApiKeysRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/account/api-keys",
  component: () => <AuthenticatedRouteGate><AccountApiKeysRouteComponent /></AuthenticatedRouteGate>,
});
const accountConnectedAppsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/account/connected-apps",
  component: () => <AuthenticatedRouteGate><AccountConnectedAppsRouteComponent /></AuthenticatedRouteGate>,
});

const routeTree = rootRoute.addChildren([
  statusRoute,
  referenceRecordsRoute,
  loginRoute,
  registerRoute,
  verifyEmailRoute,
  forgotPasswordRoute,
  resetPasswordRoute,
  authorizeRoute,
  accountRoute,
  accountSecurityRoute,
  accountSessionsRoute,
  accountApiKeysRoute,
  accountConnectedAppsRoute,
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
