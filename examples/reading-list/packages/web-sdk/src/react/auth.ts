import type { QueryClient, QueryKey } from "@tanstack/react-query";

import type {
  AuthSessionState,
  IdentityTransitionContext,
  IdentityTransitionLifecycle,
} from "../auth/index.js";
import type { QueryKeyScope } from "../client/index.js";

export interface IdentityRealtimePort {
  resetForIdentityTransition(context: IdentityTransitionContext): void | Promise<void>;
}

export interface QueryIdentityTransitionLifecycleConfiguration {
  readonly queryClient: QueryClient;
  readonly localState?: readonly {
    resetForIdentityTransition(context: IdentityTransitionContext): void | Promise<void>;
  }[];
  readonly realtime?: IdentityRealtimePort | undefined;
}

function readScopedKey(queryKey: QueryKey): Readonly<QueryKeyScope> | undefined {
  if (queryKey[0] !== "omnius") return undefined;
  const candidate = queryKey[1];
  if (typeof candidate !== "object" || candidate === null) return undefined;
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
  if (queryScope === undefined) return false;
  return (
    (scope.tenantId !== null && queryScope.tenantId === scope.tenantId) ||
    (scope.principalId !== null && queryScope.principalId === scope.principalId)
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
      await configuration.realtime?.resetForIdentityTransition(context);
      abortIfRequested(context.signal);
    },
  });
}
