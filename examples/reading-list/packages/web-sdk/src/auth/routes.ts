import { canSatisfy } from "../authorization/index.js";
import type {
  PermissionRequirement,
  PresentationResourceContext,
} from "../authorization/index.js";
import type { AuthSessionState } from "./types.js";

declare const approvedAppLocationBrand: unique symbol;
export type ApprovedAppLocation = string & {
  readonly [approvedAppLocationBrand]: true;
};

export interface AppLocationPolicy {
  readonly origin: string | URL;
  readonly approvedPathPrefixes: readonly string[];
}

export type RoutePrerequisiteResult =
  | { readonly status: "loading"; readonly reason: "session" | "tenant-transition" }
  | { readonly status: "allow" }
  | {
      readonly status: "redirect";
      readonly to: ApprovedAppLocation;
      readonly returnTo?: ApprovedAppLocation;
    }
  | {
      readonly status: "deny";
      readonly reason:
        | "authentication-error"
        | "permission-missing"
        | "capability-missing"
        | "redirect-loop";
    };

export interface RoutePrerequisiteContext {
  readonly session: AuthSessionState;
  readonly currentLocation: string;
  readonly tenantTransitioning?: boolean;
}

export interface RoutePrerequisiteConfiguration {
  readonly locations: AppLocationPolicy;
  readonly loginLocation: string;
  readonly authenticatedHomeLocation: string;
  readonly tenantSelectionLocation: string;
  readonly permissionDeniedLocation?: string;
  readonly capabilityUnavailableLocation?: string;
}

export interface RoutePrerequisites {
  requireAuthenticated(context: RoutePrerequisiteContext): RoutePrerequisiteResult;
  requireAnonymous(context: RoutePrerequisiteContext): RoutePrerequisiteResult;
  requireTenant(context: RoutePrerequisiteContext): RoutePrerequisiteResult;
  requirePermission(
    context: RoutePrerequisiteContext,
    requirement: PermissionRequirement,
    resourceContext?: PresentationResourceContext,
  ): RoutePrerequisiteResult;
  requireCapability(
    context: RoutePrerequisiteContext,
    availableCapabilityIds: readonly string[],
    capabilityId: string,
  ): RoutePrerequisiteResult;
}

const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;

function normalizePolicyOrigin(value: string | URL): string {
  const parsed = value instanceof URL ? value : new URL(value);
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
    parsed.username.length > 0 ||
    parsed.password.length > 0 ||
    parsed.pathname !== "/" ||
    parsed.search.length > 0 ||
    parsed.hash.length > 0
  ) {
    throw new TypeError("App location origin must be a credential-free HTTP(S) origin.");
  }
  return parsed.origin;
}

function decodedSafetyValue(value: string): string {
  let decoded = value;
  for (let pass = 0; pass < 3; pass += 1) {
    let next: string;
    try {
      next = decodeURIComponent(decoded);
    } catch (error: unknown) {
      throw new TypeError("App location contains malformed percent encoding.", { cause: error });
    }
    if (next === decoded) {
      break;
    }
    decoded = next;
  }
  return decoded;
}

function normalizeApprovedPrefix(prefix: string, origin: string): string {
  if (
    prefix.length === 0 ||
    prefix.trim() !== prefix ||
    !prefix.startsWith("/") ||
    prefix.startsWith("//") ||
    prefix.includes("\\") ||
    prefix.includes("?") ||
    prefix.includes("#") ||
    CONTROL_CHARACTER.test(prefix)
  ) {
    throw new TypeError("Approved app path prefixes must be clean root-relative paths.");
  }
  const parsed = new URL(prefix, origin);
  if (parsed.origin !== origin) {
    throw new TypeError("Approved app path prefixes must be same-origin.");
  }
  return parsed.pathname.length > 1 && parsed.pathname.endsWith("/")
    ? parsed.pathname.slice(0, -1)
    : parsed.pathname;
}

function pathMatchesPrefix(pathname: string, prefix: string): boolean {
  return prefix === "/" || pathname === prefix || pathname.startsWith(`${prefix}/`);
}

/**
 * Validates and normalizes an explicitly approved same-origin app-relative location.
 * Protocol-relative, external, control-character, encoded escape, and backslash inputs fail closed.
 */
export function validateAppRelativeLocation(
  value: string,
  policy: AppLocationPolicy,
): ApprovedAppLocation {
  if (
    value.length === 0 ||
    value.length > 2_048 ||
    value.trim() !== value ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.includes("\\") ||
    CONTROL_CHARACTER.test(value)
  ) {
    throw new TypeError("App location must be a clean root-relative location.");
  }
  const decoded = decodedSafetyValue(value);
  if (
    decoded.startsWith("//") ||
    decoded.includes("\\") ||
    CONTROL_CHARACTER.test(decoded)
  ) {
    throw new TypeError("App location contains an unsafe encoded value.");
  }
  const origin = normalizePolicyOrigin(policy.origin);
  const parsed = new URL(value, origin);
  if (parsed.origin !== origin || parsed.username.length > 0 || parsed.password.length > 0) {
    throw new TypeError("App location must remain on the approved application origin.");
  }
  if (policy.approvedPathPrefixes.length === 0) {
    throw new TypeError("At least one approved app path prefix is required.");
  }
  let approved = false;
  for (const configuredPrefix of policy.approvedPathPrefixes) {
    const prefix = normalizeApprovedPrefix(configuredPrefix, origin);
    if (pathMatchesPrefix(parsed.pathname, prefix)) {
      approved = true;
      break;
    }
  }
  if (!approved) {
    throw new TypeError("App location is outside the approved application paths.");
  }
  return `${parsed.pathname}${parsed.search}${parsed.hash}` as ApprovedAppLocation;
}

function addApprovedReturnTo(
  destination: ApprovedAppLocation,
  returnTo: ApprovedAppLocation,
  policy: AppLocationPolicy,
): ApprovedAppLocation {
  const origin = normalizePolicyOrigin(policy.origin);
  const parsed = new URL(destination, origin);
  parsed.searchParams.set("returnTo", returnTo);
  return validateAppRelativeLocation(
    `${parsed.pathname}${parsed.search}${parsed.hash}`,
    policy,
  );
}

function redirectUnlessLoop(
  destination: ApprovedAppLocation,
  current: ApprovedAppLocation,
  returnTo?: ApprovedAppLocation,
): RoutePrerequisiteResult {
  const comparisonOrigin = "https://route-comparison.invalid";
  if (
    new URL(destination, comparisonOrigin).pathname ===
    new URL(current, comparisonOrigin).pathname
  ) {
    return Object.freeze({ status: "deny", reason: "redirect-loop" });
  }
  return Object.freeze({
    status: "redirect",
    to: destination,
    ...(returnTo === undefined ? {} : { returnTo }),
  });
}

function sessionGate(context: RoutePrerequisiteContext): RoutePrerequisiteResult | undefined {
  if (context.tenantTransitioning === true) {
    return Object.freeze({ status: "loading", reason: "tenant-transition" });
  }
  if (context.session.status === "loading") {
    return Object.freeze({ status: "loading", reason: "session" });
  }
  if (context.session.status === "error") {
    return Object.freeze({ status: "deny", reason: "authentication-error" });
  }
  return undefined;
}

export function createRoutePrerequisites(
  configuration: RoutePrerequisiteConfiguration,
): RoutePrerequisites {
  const loginLocation = validateAppRelativeLocation(
    configuration.loginLocation,
    configuration.locations,
  );
  const authenticatedHomeLocation = validateAppRelativeLocation(
    configuration.authenticatedHomeLocation,
    configuration.locations,
  );
  const tenantSelectionLocation = validateAppRelativeLocation(
    configuration.tenantSelectionLocation,
    configuration.locations,
  );
  const permissionDeniedLocation =
    configuration.permissionDeniedLocation === undefined
      ? undefined
      : validateAppRelativeLocation(
          configuration.permissionDeniedLocation,
          configuration.locations,
        );
  const capabilityUnavailableLocation =
    configuration.capabilityUnavailableLocation === undefined
      ? undefined
      : validateAppRelativeLocation(
          configuration.capabilityUnavailableLocation,
          configuration.locations,
        );

  const requireAuthenticated = (
    context: RoutePrerequisiteContext,
  ): RoutePrerequisiteResult => {
    const gate = sessionGate(context);
    if (gate !== undefined) {
      return gate;
    }
    if (context.session.status === "authenticated") {
      return Object.freeze({ status: "allow" });
    }
    const current = validateAppRelativeLocation(
      context.currentLocation,
      configuration.locations,
    );
    const destination = addApprovedReturnTo(
      loginLocation,
      current,
      configuration.locations,
    );
    return redirectUnlessLoop(destination, current, current);
  };

  const requireAnonymous = (context: RoutePrerequisiteContext): RoutePrerequisiteResult => {
    const gate = sessionGate(context);
    if (gate !== undefined) {
      return gate;
    }
    if (context.session.status === "anonymous") {
      return Object.freeze({ status: "allow" });
    }
    const current = validateAppRelativeLocation(
      context.currentLocation,
      configuration.locations,
    );
    return redirectUnlessLoop(authenticatedHomeLocation, current);
  };

  const requireTenant = (context: RoutePrerequisiteContext): RoutePrerequisiteResult => {
    const authenticated = requireAuthenticated(context);
    if (authenticated.status !== "allow") {
      return authenticated;
    }
    if (context.session.status !== "authenticated") {
      return Object.freeze({ status: "deny", reason: "authentication-error" });
    }
    if (context.session.tenant !== null) {
      return Object.freeze({ status: "allow" });
    }
    const current = validateAppRelativeLocation(
      context.currentLocation,
      configuration.locations,
    );
    const destination = addApprovedReturnTo(
      tenantSelectionLocation,
      current,
      configuration.locations,
    );
    return redirectUnlessLoop(destination, current, current);
  };

  const requirePermission = (
    context: RoutePrerequisiteContext,
    requirement: PermissionRequirement,
    resourceContext?: PresentationResourceContext,
  ): RoutePrerequisiteResult => {
    const authenticated = requireAuthenticated(context);
    if (authenticated.status !== "allow") {
      return authenticated;
    }
    if (
      context.session.status === "authenticated" &&
      canSatisfy(context.session.presentation, requirement, resourceContext)
    ) {
      return Object.freeze({ status: "allow" });
    }
    if (permissionDeniedLocation === undefined) {
      return Object.freeze({ status: "deny", reason: "permission-missing" });
    }
    const current = validateAppRelativeLocation(
      context.currentLocation,
      configuration.locations,
    );
    return redirectUnlessLoop(permissionDeniedLocation, current);
  };

  const requireCapability = (
    context: RoutePrerequisiteContext,
    availableCapabilityIds: readonly string[],
    capabilityId: string,
  ): RoutePrerequisiteResult => {
    const gate = sessionGate(context);
    if (gate !== undefined) {
      return gate;
    }
    if (availableCapabilityIds.includes(capabilityId)) {
      return Object.freeze({ status: "allow" });
    }
    if (capabilityUnavailableLocation === undefined) {
      return Object.freeze({ status: "deny", reason: "capability-missing" });
    }
    const current = validateAppRelativeLocation(
      context.currentLocation,
      configuration.locations,
    );
    return redirectUnlessLoop(capabilityUnavailableLocation, current);
  };

  return Object.freeze({
    requireAuthenticated,
    requireAnonymous,
    requireTenant,
    requirePermission,
    requireCapability,
  });
}
