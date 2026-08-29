import {
  createRoutePrerequisites,
  validateAppRelativeLocation,
  type AppLocationPolicy,
} from "@omnius/web-sdk/auth";
import { useSession } from "@omnius/web-sdk/react";
import { Navigate, useRouterState } from "@tanstack/react-router";
import type { ReactNode } from "react";

import { LoadingState, ProblemState } from "../components/request-states";

function appLocationPolicy(): AppLocationPolicy {
  return Object.freeze({
    origin: globalThis.location.origin,
    approvedPathPrefixes: ["/"],
  });
}

export function validateReturnTo(value: string | undefined, fallback = "/account"): string {
  if (value === undefined) return fallback;
  try {
    return validateAppRelativeLocation(value, appLocationPolicy());
  } catch {
    return fallback;
  }
}

function useRoutePrerequisite(kind: "anonymous" | "authenticated") {
  const sessionQuery = useSession();
  const currentLocation = useRouterState({ select: (state) => state.location.href });
  const prerequisites = createRoutePrerequisites({
    locations: appLocationPolicy(),
    loginLocation: "/login",
    authenticatedHomeLocation: "/account",
    tenantSelectionLocation: "/account",
  });
  const session = sessionQuery.data;
  if (session === undefined || sessionQuery.isPending) {
    return Object.freeze({ status: "loading" as const });
  }
  return kind === "authenticated"
    ? prerequisites.requireAuthenticated({ session, currentLocation })
    : prerequisites.requireAnonymous({ session, currentLocation });
}

export function AuthenticatedRouteGate({ children }: { readonly children: ReactNode }) {
  const prerequisite = useRoutePrerequisite("authenticated");
  if (prerequisite.status === "loading") return <LoadingState label="Checking your session" />;
  if (prerequisite.status === "deny") {
    return <ProblemState error={new Error("Your session could not be verified.")} />;
  }
  if (prerequisite.status === "redirect") {
    return (
      <Navigate
        to="/login"
        search={{ returnTo: prerequisite.returnTo ?? "/account" }}
        replace
      />
    );
  }
  return children;
}

export function AnonymousRouteGate({ children }: { readonly children: ReactNode }) {
  const prerequisite = useRoutePrerequisite("anonymous");
  if (prerequisite.status === "loading") return <LoadingState label="Checking your session" />;
  if (prerequisite.status === "deny") {
    return <ProblemState error={new Error("Your session could not be verified.")} />;
  }
  if (prerequisite.status === "redirect") return <Navigate to="/account" replace />;
  return children;
}
