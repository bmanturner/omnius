import type { QueryClient, QueryKey } from "@tanstack/react-query";

import { scopeQueryKey } from "../client/index.js";
import type { QueryKeyScope } from "../client/index.js";
import type {
  AuthSessionState,
  IdentityTransitionContext,
  IdentityTransitionLifecycle,
} from "../auth/index.js";

export interface TenantLocalStatePort {
  resetForTenantTransition(context: TenantTransitionContext): void | Promise<void>;
}

export interface TenantRealtimePort {
  reestablishForTenant(context: TenantTransitionContext): void | Promise<void>;
}

export interface TenantRoutePort {
  replaceTenantRoute(context: TenantTransitionContext): void | Promise<void>;
}

export interface IdentityRealtimePort {
  resetForIdentityTransition(context: IdentityTransitionContext): void | Promise<void>;
}

export interface TenantTransitionContext {
  readonly previous: Readonly<QueryKeyScope>;
  readonly next: Readonly<QueryKeyScope>;
  readonly signal?: AbortSignal;
}

export type TenantTransitionState =
  | {
      readonly status: "ready";
      readonly scope: Readonly<QueryKeyScope>;
    }
  | {
      readonly status: "transitioning";
      readonly previous: Readonly<QueryKeyScope>;
      readonly next: Readonly<QueryKeyScope>;
    }
  | {
      readonly status: "error";
      readonly previous: Readonly<QueryKeyScope>;
      readonly next: Readonly<QueryKeyScope>;
    };

export interface TenantTransitionCoordinator {
  getSnapshot(): TenantTransitionState;
  subscribe(listener: (state: TenantTransitionState) => void): () => void;
  switchTenant(next: QueryKeyScope, options?: { readonly signal?: AbortSignal }): Promise<void>;
  dispose(): void;
}

export interface TenantTransitionCoordinatorConfiguration {
  readonly queryClient: QueryClient;
  readonly initialScope: QueryKeyScope;
  readonly localState: readonly TenantLocalStatePort[];
  readonly realtime: TenantRealtimePort;
  readonly route: TenantRoutePort;
  readonly queryPolicy?: "remove" | "invalidate";
}

export interface QueryIdentityTransitionLifecycleConfiguration {
  readonly queryClient: QueryClient;
  readonly localState?: readonly {
    resetForIdentityTransition(context: IdentityTransitionContext): void | Promise<void>;
  }[];
  readonly realtime: IdentityRealtimePort;
}

export class TenantTransitionInProgressError extends Error {
  override readonly name = "TenantTransitionInProgressError";

  constructor() {
    super("A tenant transition is already active.");
  }
}

function validateScope(scope: QueryKeyScope): Readonly<QueryKeyScope> {
  for (const [name, value] of [
    ["tenantId", scope.tenantId],
    ["principalId", scope.principalId],
    ["permissionScope", scope.permissionScope],
  ] as const) {
    if (
      value !== undefined &&
      value !== null &&
      (value.length === 0 || value.trim() !== value)
    ) {
      throw new TypeError(`${name} must be null or a non-empty trimmed value.`);
    }
  }
  return Object.freeze({
    tenantId: scope.tenantId,
    principalId: scope.principalId,
    ...(scope.permissionScope === undefined
      ? {}
      : { permissionScope: scope.permissionScope }),
  });
}

function readScopedKey(queryKey: QueryKey): Readonly<QueryKeyScope> | undefined {
  if (queryKey[0] !== "omnius") {
    return undefined;
  }
  const candidate = queryKey[1];
  if (typeof candidate !== "object" || candidate === null) {
    return undefined;
  }
  const tenantId = Reflect.get(candidate, "tenantId");
  const principalId = Reflect.get(candidate, "principalId");
  if (
    (tenantId !== null && typeof tenantId !== "string") ||
    (principalId !== null && typeof principalId !== "string")
  ) {
    return undefined;
  }
  return candidate as Readonly<QueryKeyScope>;
}

function queryBelongsToScope(queryKey: QueryKey, scope: QueryKeyScope): boolean {
  const queryScope = readScopedKey(queryKey);
  if (queryScope === undefined) {
    return false;
  }
  return (
    (scope.tenantId !== null && queryScope.tenantId === scope.tenantId) ||
    (scope.principalId !== null && queryScope.principalId === scope.principalId)
  );
}

function queryBelongsToTenantTransition(
  queryKey: QueryKey,
  scope: QueryKeyScope,
): boolean {
  const queryScope = readScopedKey(queryKey);
  if (queryScope === undefined) {
    return false;
  }
  return (
    (scope.tenantId !== null && queryScope.tenantId === scope.tenantId) ||
    (queryScope.tenantId === null &&
      scope.principalId !== null &&
      queryScope.principalId === scope.principalId)
  );
}

function scopeFromSession(session: AuthSessionState): Readonly<QueryKeyScope> {
  if (session.status !== "authenticated") {
    return Object.freeze({ tenantId: null, principalId: null });
  }
  return Object.freeze({
    tenantId: session.tenant?.id ?? null,
    principalId: session.principal.subject,
    permissionScope: JSON.stringify(session.presentation),
  });
}

function abortIfRequested(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw signal.reason ?? new DOMException("Aborted", "AbortError");
  }
}

/** Uses the T137 scoped-key contract for every tenant-aware generated query key. */
export function scopeTenantQueryKey<const TKey extends readonly unknown[]>(
  generatedKey: TKey,
  scope: QueryKeyScope,
): readonly ["omnius", Readonly<QueryKeyScope>, ...TKey] {
  return scopeQueryKey(generatedKey, validateScope(scope));
}

/**
 * Creates identity cleanup for auth managers. Cancellation always completes before removal,
 * tenant-local resets, and realtime teardown/reconnection.
 */
export function createQueryIdentityTransitionLifecycle(
  configuration: QueryIdentityTransitionLifecycleConfiguration,
): IdentityTransitionLifecycle {
  return Object.freeze({
    async transition(context: IdentityTransitionContext): Promise<void> {
      const previousScope = scopeFromSession(context.previous);
      const predicate = (query: { readonly queryKey: QueryKey }): boolean =>
        queryBelongsToScope(query.queryKey, previousScope);
      await configuration.queryClient.cancelQueries({ predicate });
      abortIfRequested(context.signal);
      configuration.queryClient.removeQueries({ predicate });
      for (const localState of configuration.localState ?? []) {
        await localState.resetForIdentityTransition(context);
        abortIfRequested(context.signal);
      }
      await configuration.realtime.resetForIdentityTransition(context);
      abortIfRequested(context.signal);
    },
  });
}

/**
 * Coordinates a tenant transition without exposing stale old-tenant data between phases.
 * Observers see `transitioning` synchronously before query cancellation begins.
 */
export function createTenantTransitionCoordinator(
  configuration: TenantTransitionCoordinatorConfiguration,
): TenantTransitionCoordinator {
  let state: TenantTransitionState = Object.freeze({
    status: "ready",
    scope: validateScope(configuration.initialScope),
  });
  let active = false;
  let disposed = false;
  const listeners = new Set<(state: TenantTransitionState) => void>();

  const publish = (next: TenantTransitionState): void => {
    state = next;
    for (const listener of listeners) {
      try {
        listener(next);
      } catch {
        // A view subscriber must not interrupt tenant isolation.
      }
    }
  };

  return Object.freeze({
    getSnapshot(): TenantTransitionState {
      return state;
    },
    subscribe(listener: (snapshot: TenantTransitionState) => void): () => void {
      if (disposed) {
        throw new Error("The tenant transition coordinator is disposed.");
      }
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    async switchTenant(
      nextInput: QueryKeyScope,
      options: { readonly signal?: AbortSignal } = {},
    ): Promise<void> {
      if (disposed) {
        throw new Error("The tenant transition coordinator is disposed.");
      }
      if (active) {
        throw new TenantTransitionInProgressError();
      }
      if (state.status !== "ready") {
        throw new TenantTransitionInProgressError();
      }
      const previous = state.scope;
      const next = validateScope(nextInput);
      if (
        previous.tenantId === next.tenantId &&
        previous.principalId === next.principalId &&
        previous.permissionScope === next.permissionScope
      ) {
        return;
      }
      active = true;
      const context: TenantTransitionContext = Object.freeze({
        previous,
        next,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      publish(Object.freeze({ status: "transitioning", previous, next }));
      const predicate = (query: { readonly queryKey: QueryKey }): boolean =>
        queryBelongsToTenantTransition(query.queryKey, previous);
      try {
        abortIfRequested(options.signal);
        await configuration.queryClient.cancelQueries({ predicate });
        abortIfRequested(options.signal);
        if ((configuration.queryPolicy ?? "remove") === "remove") {
          configuration.queryClient.removeQueries({ predicate });
        } else {
          await configuration.queryClient.invalidateQueries({ predicate });
        }
        abortIfRequested(options.signal);
        for (const localState of configuration.localState) {
          await localState.resetForTenantTransition(context);
          abortIfRequested(options.signal);
        }
        await configuration.realtime.reestablishForTenant(context);
        abortIfRequested(options.signal);
        await configuration.route.replaceTenantRoute(context);
        abortIfRequested(options.signal);
        publish(Object.freeze({ status: "ready", scope: next }));
      } catch (error: unknown) {
        publish(Object.freeze({ status: "error", previous, next }));
        throw error;
      } finally {
        active = false;
      }
    },
    dispose(): void {
      disposed = true;
      listeners.clear();
    },
  });
}
