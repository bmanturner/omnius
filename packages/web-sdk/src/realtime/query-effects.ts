import { scopeQueryKey } from "../client/pagination.js";
import type { QueryKeyScope } from "../client/pagination.js";
import type { DomainEventV1 } from "../internal/generated/realtime.js";

export type RealtimeQueryKey = readonly unknown[];
export type QueryEffectResult = void | Promise<void>;

/** The cache operations required by the framework-neutral effect engine. */
export interface RealtimeQueryClient {
  invalidateQueries(queryKey: RealtimeQueryKey): QueryEffectResult;
  refetchQueries(queryKey: RealtimeQueryKey): QueryEffectResult;
  removeQueries(queryKey: RealtimeQueryKey): QueryEffectResult;
  setQueryData<TData>(
    queryKey: RealtimeQueryKey,
    updater: (current: TData | undefined) => TData | undefined,
  ): QueryEffectResult;
}

export type GeneratedQueryKeyFactory<TEvent extends DomainEventV1> = (
  event: TEvent,
) => RealtimeQueryKey;

/**
 * A generated key factory and the authorization scope that must be applied to its result.
 * The engine never accepts or constructs an operation-name cache key itself.
 */
export interface RealtimeQueryTarget<TEvent extends DomainEventV1> {
  readonly generatedKeyFactory: GeneratedQueryKeyFactory<TEvent>;
  readonly scope: (event: TEvent) => QueryKeyScope;
}

interface TargetedQueryEffect<TEvent extends DomainEventV1> {
  readonly target: RealtimeQueryTarget<TEvent>;
}

/** Omitting `type` deliberately selects the safe default: invalidation. */
export interface InvalidateQueryEffect<TEvent extends DomainEventV1>
  extends TargetedQueryEffect<TEvent> {
  readonly type?: "invalidate";
}

export interface RefetchQueryEffect<TEvent extends DomainEventV1>
  extends TargetedQueryEffect<TEvent> {
  readonly type: "refetch";
}

export interface RemoveQueryEffect<TEvent extends DomainEventV1>
  extends TargetedQueryEffect<TEvent> {
  readonly type: "remove";
}

export interface PreferCacheConflictPolicy {
  readonly type: "prefer-cache";
}

export interface PreferEventConflictPolicy {
  readonly type: "prefer-event";
}

export type QueryRevision = number | bigint;

export interface NewerRevisionConflictPolicy<TData> {
  readonly type: "newer-revision";
  /** Reads a resource-local revision. No event ordering is inferred by the engine. */
  readonly revision: (representation: TData) => QueryRevision;
}

export type CompleteRepresentationConflictPolicy<TData> =
  | PreferCacheConflictPolicy
  | PreferEventConflictPolicy
  | NewerRevisionConflictPolicy<TData>;

export interface SetCompleteQueryEffect<
  TEvent extends DomainEventV1,
  TData,
> extends TargetedQueryEffect<TEvent> {
  readonly type: "set-complete";
  /** Selects an untrusted candidate from an already validated event envelope. */
  readonly select: (event: TEvent) => unknown;
  /** Must confirm that the candidate is a complete, cache-compatible representation. */
  readonly validateComplete: (candidate: unknown) => candidate is TData;
  readonly conflictPolicy: CompleteRepresentationConflictPolicy<TData>;
}

export interface RevalidateSessionQueryEffect {
  readonly type: "revalidate-session";
}

export interface RevalidateCapabilitiesQueryEffect {
  readonly type: "revalidate-capabilities";
}

export type RealtimeQueryEffect<
  TEvent extends DomainEventV1,
  TData = unknown,
> =
  | InvalidateQueryEffect<TEvent>
  | RefetchQueryEffect<TEvent>
  | SetCompleteQueryEffect<TEvent, TData>
  | RemoveQueryEffect<TEvent>
  | RevalidateSessionQueryEffect
  | RevalidateCapabilitiesQueryEffect;

export type RealtimeQueryEffectKind =
  | "invalidate"
  | "refetch"
  | "set-complete"
  | "remove"
  | "revalidate-session"
  | "revalidate-capabilities";

export type RealtimeQueryEffectDiagnosticCode =
  | "target-resolution-failed"
  | "complete-representation-rejected"
  | "effect-execution-failed";

/** Diagnostics contain identifiers only; event payloads and thrown error details are excluded. */
export interface RealtimeQueryEffectDiagnostic {
  readonly code: RealtimeQueryEffectDiagnosticCode;
  readonly eventType: string;
  readonly effect: RealtimeQueryEffectKind;
}

interface StoredEffect {
  readonly kind: RealtimeQueryEffectKind;
  readonly execute: (
    context: EffectExecutionContext,
    event: DomainEventV1,
  ) => Promise<void>;
}

export interface RealtimeQueryEffectRegistry {
  /**
   * Registers one effect for an exact validated domain-event type. Register additional effects
   * with additional calls; the returned function removes only this registration.
   */
  register<TEventType extends string, TData = unknown>(
    eventType: TEventType,
    effect: RealtimeQueryEffect<
      DomainEventV1 & { readonly type: TEventType },
      TData
    >,
  ): () => void;
}

interface InternalRealtimeQueryEffectRegistry extends RealtimeQueryEffectRegistry {
  effectsFor(eventType: string): readonly StoredEffect[];
}

export interface RealtimeQueryEffectEngine {
  /** Applies the registered effects for an already decoder-validated domain event. */
  apply(event: DomainEventV1): Promise<void>;
}

export interface CreateRealtimeQueryEffectEngineOptions {
  readonly queryClient: RealtimeQueryClient;
  readonly registry: RealtimeQueryEffectRegistry;
  readonly revalidateSession: () => QueryEffectResult;
  readonly revalidateCapabilities: () => QueryEffectResult;
  readonly onDiagnostic?: (diagnostic: RealtimeQueryEffectDiagnostic) => void;
}

interface EffectExecutionContext {
  readonly queryClient: RealtimeQueryClient;
  readonly revalidateSession: () => QueryEffectResult;
  readonly revalidateCapabilities: () => QueryEffectResult;
  readonly diagnose: (
    eventType: string,
    effect: RealtimeQueryEffectKind,
    code: RealtimeQueryEffectDiagnosticCode,
  ) => void;
}

function assertEventType(eventType: string): void {
  if (eventType.length === 0 || eventType.trim() !== eventType) {
    throw new TypeError("Realtime query effects require a non-empty, trimmed event type.");
  }
}

function createTargetResolver<TEvent extends DomainEventV1>(
  target: RealtimeQueryTarget<TEvent>,
): (event: DomainEventV1) => RealtimeQueryKey {
  const generatedKeyFactory = target.generatedKeyFactory;
  const readScope = target.scope;
  return (event) => {
    const typedEvent = event as TEvent;
    return scopeQueryKey(generatedKeyFactory(typedEvent), readScope(typedEvent));
  };
}

async function invalidateAfterRejectedComplete(
  context: EffectExecutionContext,
  eventType: string,
  queryKey: RealtimeQueryKey,
): Promise<void> {
  try {
    await context.queryClient.invalidateQueries(queryKey);
  } catch {
    context.diagnose(eventType, "set-complete", "effect-execution-failed");
  }
}

function isUsableRevision(revision: QueryRevision): boolean {
  return typeof revision === "bigint" || Number.isFinite(revision);
}

function compileEffect<TEvent extends DomainEventV1, TData>(
  effect: RealtimeQueryEffect<TEvent, TData>,
): StoredEffect {
  if (effect.type === "revalidate-session") {
    return {
      kind: "revalidate-session",
      execute: async (context) => {
        await context.revalidateSession();
      },
    };
  }

  if (effect.type === "revalidate-capabilities") {
    return {
      kind: "revalidate-capabilities",
      execute: async (context) => {
        await context.revalidateCapabilities();
      },
    };
  }

  const resolveTarget = createTargetResolver(effect.target);

  if (effect.type === "set-complete") {
    const select = effect.select;
    const validateComplete = effect.validateComplete;
    const conflictPolicy = effect.conflictPolicy;

    return {
      kind: "set-complete",
      execute: async (context, event) => {
        let queryKey: RealtimeQueryKey;
        try {
          queryKey = resolveTarget(event);
        } catch {
          context.diagnose(event.type, "set-complete", "target-resolution-failed");
          return;
        }

        let candidate: unknown;
        try {
          candidate = select(event as TEvent);
          if (!validateComplete(candidate)) {
            context.diagnose(
              event.type,
              "set-complete",
              "complete-representation-rejected",
            );
            await invalidateAfterRejectedComplete(context, event.type, queryKey);
            return;
          }

          const complete = candidate;
          await context.queryClient.setQueryData<TData>(queryKey, (current) => {
            if (conflictPolicy.type === "prefer-event") {
              return complete;
            }
            if (conflictPolicy.type === "prefer-cache") {
              return current === undefined ? complete : current;
            }
            if (current === undefined) {
              return complete;
            }

            const currentRevision = conflictPolicy.revision(current);
            const eventRevision = conflictPolicy.revision(complete);
            if (
              !isUsableRevision(currentRevision) ||
              !isUsableRevision(eventRevision) ||
              typeof currentRevision !== typeof eventRevision
            ) {
              throw new TypeError("Complete representation revisions are not comparable.");
            }
            return eventRevision > currentRevision ? complete : current;
          });
        } catch {
          context.diagnose(event.type, "set-complete", "effect-execution-failed");
          await invalidateAfterRejectedComplete(context, event.type, queryKey);
        }
      },
    };
  }

  const kind = effect.type ?? "invalidate";
  return {
    kind,
    execute: async (context, event) => {
      let queryKey: RealtimeQueryKey;
      try {
        queryKey = resolveTarget(event);
      } catch {
        context.diagnose(event.type, kind, "target-resolution-failed");
        return;
      }

      if (kind === "refetch") {
        await context.queryClient.refetchQueries(queryKey);
      } else if (kind === "remove") {
        await context.queryClient.removeQueries(queryKey);
      } else {
        await context.queryClient.invalidateQueries(queryKey);
      }
    },
  };
}

export function createRealtimeQueryEffectRegistry(): RealtimeQueryEffectRegistry {
  const effects = new Map<string, Map<symbol, StoredEffect>>();

  const registry: InternalRealtimeQueryEffectRegistry = {
    register<TEventType extends string, TData = unknown>(
      eventType: TEventType,
      effect: RealtimeQueryEffect<
        DomainEventV1 & { readonly type: TEventType },
        TData
      >,
    ): () => void {
      assertEventType(eventType);
      const registration = Symbol(eventType);
      const stored = compileEffect(effect);
      let eventEffects = effects.get(eventType);
      if (eventEffects === undefined) {
        eventEffects = new Map();
        effects.set(eventType, eventEffects);
      }
      eventEffects.set(registration, stored);

      let registered = true;
      return () => {
        if (!registered) {
          return;
        }
        registered = false;
        const current = effects.get(eventType);
        current?.delete(registration);
        if (current?.size === 0) {
          effects.delete(eventType);
        }
      };
    },

    effectsFor(eventType: string): readonly StoredEffect[] {
      return [...(effects.get(eventType)?.values() ?? [])];
    },
  };

  return registry;
}

function readInternalRegistry(
  registry: RealtimeQueryEffectRegistry,
): InternalRealtimeQueryEffectRegistry {
  const candidate = registry as Partial<InternalRealtimeQueryEffectRegistry>;
  if (typeof candidate.effectsFor !== "function") {
    throw new TypeError(
      "Realtime query effect engine requires a registry created by createRealtimeQueryEffectRegistry().",
    );
  }
  return candidate as InternalRealtimeQueryEffectRegistry;
}

export function createRealtimeQueryEffectEngine(
  options: CreateRealtimeQueryEffectEngineOptions,
): RealtimeQueryEffectEngine {
  const registry = readInternalRegistry(options.registry);
  const context: EffectExecutionContext = {
    queryClient: options.queryClient,
    revalidateSession: options.revalidateSession,
    revalidateCapabilities: options.revalidateCapabilities,
    diagnose(eventType, effect, code): void {
      if (options.onDiagnostic === undefined) {
        return;
      }
      try {
        options.onDiagnostic({ code, eventType, effect });
      } catch {
        // Diagnostic consumers must not interrupt realtime delivery.
      }
    },
  };

  return {
    async apply(event): Promise<void> {
      for (const effect of registry.effectsFor(event.type)) {
        try {
          await effect.execute(context, event);
        } catch {
          context.diagnose(event.type, effect.kind, "effect-execution-failed");
        }
      }
    },
  };
}
