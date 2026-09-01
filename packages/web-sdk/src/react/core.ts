import {
  QueryClient,
  QueryClientProvider,
  useQuery,
} from "@tanstack/react-query";
import type {
  QueryClientConfig,
  UseQueryResult,
} from "@tanstack/react-query";
import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useMemo,
  useState,
  useSyncExternalStore,
} from "react";
import type { ReactNode } from "react";

import type {
  AuthManager,
  AuthSessionState,
  PublicPrincipal,
} from "../auth/index.js";
import {
  can,
  canSatisfy,
} from "../authorization/index.js";
import type {
  PermissionId,
  PermissionRequirement,
  PresentationResourceContext,
} from "../authorization/index.js";
import type { CapabilityRegistry } from "../capabilities/index.js";
import { scopeTenantQueryKey } from "./query-scope.js";

import {
  createServiceClient,
  ServiceClientError,
  ServiceProblemError,
} from "../client/index.js";
import type {
  ContractMismatchNotification,
  DefinedServiceClientConfiguration,
  ServiceClient,
} from "../client/index.js";
import {
  getGetCurrentPrincipalQueryKey,
  getGetLivenessQueryKey,
  getGetReadinessQueryKey,
  getGetReferenceRecordQueryKey,
  getGetRuntimeMetadataQueryKey,
  getGetStartupQueryKey,
  getGetVersionQueryKey,
  getListReferenceRecordsQueryKey,
} from "../internal/generated/http/react-query.js";

export * as serviceQueries from "../internal/generated/http/react-query.js";

export const SERVICE_QUERY_STALE_TIME_MS = 30_000;
export const SERVICE_QUERY_GC_TIME_MS = 5 * 60_000;
export const SERVICE_QUERY_MAX_RETRIES = 2;

const nonRetryableProblemStatuses: Readonly<Record<number, true>> = {
  400: true,
  401: true,
  403: true,
  404: true,
  409: true,
  412: true,
  413: true,
  415: true,
  422: true,
  428: true,
};

/**
 * Stable generated key factories exposed by operation identity. Consumers scope these with
 * `scopeQueryKey` from the framework-neutral client entry rather than writing cache strings.
 */
export const serviceQueryKeys = Object.freeze({
  getCurrentPrincipal: getGetCurrentPrincipalQueryKey,
  getLiveness: getGetLivenessQueryKey,
  getReadiness: getGetReadinessQueryKey,
  getReferenceRecord: getGetReferenceRecordQueryKey,
  getRuntimeMetadata: getGetRuntimeMetadataQueryKey,
  getStartup: getGetStartupQueryKey,
  getVersion: getGetVersionQueryKey,
  listReferenceRecords: getListReferenceRecordsQueryKey,
});

/** Queries retry only normalized transient failures, never caller or client errors. */
export function shouldRetryServiceQuery(failureCount: number, error: unknown): boolean {
  if (failureCount >= SERVICE_QUERY_MAX_RETRIES || !(error instanceof ServiceClientError)) {
    return false;
  }
  if (
    error instanceof ServiceProblemError &&
    nonRetryableProblemStatuses[error.status] === true
  ) {
    return false;
  }
  return error.retryable;
}

/**
 * Creates an isolated query cache with service-safe browser defaults.
 *
 * Queries are fresh for 30 seconds and retained for five minutes. They refetch when a stale
 * observer regains focus or reconnects. At most two retries are attempted for normalized,
 * retryable service failures. Mutations never retry automatically.
 */
export function createServiceQueryClient(
  configuration: QueryClientConfig = {},
): QueryClient {
  const queries = configuration.defaultOptions?.queries;
  const mutations = configuration.defaultOptions?.mutations;
  return new QueryClient({
    ...configuration,
    defaultOptions: {
      ...configuration.defaultOptions,
      queries: {
        staleTime: SERVICE_QUERY_STALE_TIME_MS,
        gcTime: SERVICE_QUERY_GC_TIME_MS,
        retry: shouldRetryServiceQuery,
        refetchOnWindowFocus: true,
        refetchOnReconnect: true,
        ...queries,
      },
      mutations: {
        retry: false,
        ...mutations,
      },
    },
  });
}

export interface ServiceErrorPresentation {
  readonly title: string;
  readonly detail: string;
  readonly requestId?: string;
}

/** Converts the normalized transport error union into a safe, display-ready problem. */
export function presentServiceError(error: unknown): ServiceErrorPresentation {
  if (error instanceof ServiceProblemError) {
    return {
      title: error.title,
      detail: error.detail ?? "The service could not complete this request.",
      ...(error.requestId === undefined ? {} : { requestId: error.requestId }),
    };
  }
  if (error instanceof ServiceClientError) {
    return {
      title: "Service request failed",
      detail: error.message,
      ...(error.requestId === undefined ? {} : { requestId: error.requestId }),
    };
  }
  return {
    title: "Unexpected application error",
    detail: "The application could not complete this request.",
  };
}

interface WebSdkContextValue {
  readonly client: ServiceClient;
  readonly authManager: AuthManager | null;
  readonly capabilityRegistry: CapabilityRegistry | null;
  readonly contractMismatch: Readonly<ContractMismatchNotification> | null;
}

const WebSdkContext = createContext<WebSdkContextValue | null>(null);

export interface WebSdkProviderProps {
  readonly configuration: Readonly<DefinedServiceClientConfiguration>;
  readonly queryClient?: QueryClient | undefined;
  readonly authManager?: AuthManager | undefined;
  readonly capabilityRegistry?: CapabilityRegistry | undefined;
  readonly children?: ReactNode;
}

/**
 * Owns one service client and one TanStack Query cache per provider instance. Generated request
 * options remain explicitly bound to the client; no process-global transport state is used.
 */
export function WebSdkProvider({
  authManager,
  capabilityRegistry,
  children,
  configuration,
  queryClient,
}: WebSdkProviderProps): ReactNode {
  const [contractMismatch, setContractMismatch] =
    useState<Readonly<ContractMismatchNotification> | null>(null);
  const client = useMemo(() => {
    if (
      authManager !== undefined &&
      configuration.auth !== undefined &&
      configuration.auth !== authManager
    ) {
      throw new TypeError(
        "WebSdkProvider received different auth managers in configuration and props.",
      );
    }
    return createServiceClient({
      ...configuration,
      ...(authManager === undefined
        ? {}
        : {
            auth: authManager,
            credentials: configuration.credentials ?? authManager.requestCredentials,
          }),
      onContractMismatch: (mismatch) => {
        setContractMismatch(mismatch);
        configuration.onContractMismatch?.(mismatch);
      },
    });
  }, [authManager, configuration]);
  const ownedQueryClient = useMemo(
    () => queryClient ?? createServiceQueryClient(),
    [queryClient],
  );
  const context = useMemo(
    () => ({
      client,
      authManager: authManager ?? null,
      capabilityRegistry: capabilityRegistry ?? null,
      contractMismatch,
    }),
    [authManager, capabilityRegistry, client, contractMismatch],
  );

  return createElement(
    WebSdkContext.Provider,
    { value: context },
    createElement(QueryClientProvider, { client: ownedQueryClient }, children),
  );
}

function useWebSdkContext(): WebSdkContextValue {
  const context = useContext(WebSdkContext);
  if (context === null) {
    throw new Error("Web SDK hooks must be used within WebSdkProvider.");
  }
  return context;
}

export function useServiceClient(): ServiceClient {
  return useWebSdkContext().client;
}

export function useClientConfiguration(): Readonly<DefinedServiceClientConfiguration> {
  return useServiceClient().configuration;
}

export function useContractMismatch(): Readonly<ContractMismatchNotification> | null {
  return useWebSdkContext().contractMismatch;
}

/** Returns the single verified capability registry owned by the application composition root. */
export function useCapabilityRegistry(): CapabilityRegistry {
  const registry = useWebSdkContext().capabilityRegistry;
  if (registry === null) {
    throw new Error("Capability hooks require a verified registry on WebSdkProvider.");
  }
  return registry;
}

function authSessionScope(state: AuthSessionState): {
  readonly tenantId: string | null;
  readonly principalId: string | null;
  readonly permissionScope?: string;
} {
  if (state.status !== "authenticated") {
    return Object.freeze({ tenantId: null, principalId: null });
  }
  return Object.freeze({
    tenantId: state.tenant?.id ?? null,
    principalId: state.principal.subject,
    permissionScope: JSON.stringify(state.presentation),
  });
}

/** Stable T137-scoped key for the authenticated principal/session Query resource. */
export function getAuthSessionQueryKey(
  state: AuthSessionState,
): readonly [
  "omnius",
  Readonly<{
    readonly tenantId: string | null;
    readonly principalId: string | null;
    readonly permissionScope?: string;
  }>,
  "auth",
  "session",
] {
  return scopeTenantQueryKey(["auth", "session"] as const, authSessionScope(state));
}

export function useAuthManager(): AuthManager {
  const authManager = useWebSdkContext().authManager;
  if (authManager === null) {
    throw new Error("Auth hooks require an explicit authManager on WebSdkProvider.");
  }
  return authManager;
}

/**
 * Reads the semantic session through TanStack Query while subscribing to manager transitions.
 * A loading snapshot remains loading; prior-principal data is never used as placeholder data.
 */
export function useSession(): UseQueryResult<AuthSessionState, Error> {
  const authManager = useAuthManager();
  const subscribe = useCallback(
    (notify: () => void) => authManager.subscribe(() => notify()),
    [authManager],
  );
  const getSnapshot = useCallback(() => authManager.getSnapshot(), [authManager]);
  const snapshot = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
  const queryKey = useMemo(() => getAuthSessionQueryKey(snapshot), [snapshot]);
  return useQuery<AuthSessionState, Error>({
    queryKey,
    queryFn: ({ signal }) => authManager.getSession({ signal }),
    initialData: snapshot,
    initialDataUpdatedAt: 0,
    retry: false,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
  });
}

export function useCurrentPrincipal(): Readonly<PublicPrincipal> | null {
  const session = useSession().data;
  return session?.status === "authenticated" ? session.principal : null;
}

export interface PermissionPresentationResult {
  readonly allowed: boolean;
  readonly isLoading: boolean;
}

/** UX-only permission hook. Backend authorization remains mandatory. */
export function usePermission(
  permission: PermissionId,
  resourceContext?: PresentationResourceContext,
): PermissionPresentationResult {
  const query = useSession();
  const session = query.data;
  const isLoading =
    query.isPending || session === undefined || session.status === "loading";
  return Object.freeze({
    allowed:
      session?.status === "authenticated" &&
      can(session.presentation, permission, resourceContext),
    isLoading,
  });
}

/** UX-only all/any permission-requirement hook. Backend authorization remains mandatory. */
export function usePermissions(
  requirement: PermissionRequirement,
  resourceContext?: PresentationResourceContext,
): PermissionPresentationResult {
  const query = useSession();
  const session = query.data;
  const isLoading =
    query.isPending || session === undefined || session.status === "loading";
  return Object.freeze({
    allowed:
      session?.status === "authenticated" &&
      canSatisfy(session.presentation, requirement, resourceContext),
    isLoading,
  });
}

const DEFAULT_AUTH_LOADING = createElement(
  "div",
  { role: "status", "aria-live": "polite", "aria-busy": true },
  "Checking your session…",
);
const DEFAULT_AUTH_DENIED = createElement(
  "div",
  { role: "alert" },
  "You must sign in to view this content.",
);
const DEFAULT_PERMISSION_DENIED = createElement(
  "div",
  { role: "alert" },
  "You do not have permission to view this content.",
);

export interface RequireAuthenticatedProps {
  readonly children?: ReactNode;
  readonly loading?: ReactNode;
  readonly denied?: ReactNode;
}

/** Prevents protected content from rendering during bootstrap or identity transitions. */
export function RequireAuthenticated({
  children,
  loading = DEFAULT_AUTH_LOADING,
  denied = DEFAULT_AUTH_DENIED,
}: RequireAuthenticatedProps): ReactNode {
  const query = useSession();
  const session = query.data;
  if (query.isPending || session === undefined || session.status === "loading") {
    return loading;
  }
  return session.status === "authenticated" ? children : denied;
}

export interface RequirePermissionProps {
  readonly permission?: PermissionId;
  readonly requirement?: PermissionRequirement;
  readonly resourceContext?: PresentationResourceContext;
  readonly children?: ReactNode;
  readonly loading?: ReactNode;
  readonly denied?: ReactNode;
}

/**
 * Presentation-only guard with accessible loading and denial defaults.
 * It must never replace backend authorization.
 */
export function RequirePermission({
  permission,
  requirement,
  resourceContext,
  children,
  loading = DEFAULT_AUTH_LOADING,
  denied = DEFAULT_PERMISSION_DENIED,
}: RequirePermissionProps): ReactNode {
  if ((permission === undefined) === (requirement === undefined)) {
    throw new TypeError("RequirePermission needs exactly one permission or requirement.");
  }
  const query = useSession();
  const session = query.data;
  if (query.isPending || session === undefined || session.status === "loading") {
    return loading;
  }
  if (session.status !== "authenticated") {
    return denied;
  }
  let allowed: boolean;
  if (permission !== undefined) {
    allowed = can(session.presentation, permission, resourceContext);
  } else if (requirement !== undefined) {
    allowed = canSatisfy(session.presentation, requirement, resourceContext);
  } else {
    throw new TypeError("RequirePermission needs exactly one permission or requirement.");
  }
  return allowed ? children : denied;
}

export * from "./query-scope.js";
