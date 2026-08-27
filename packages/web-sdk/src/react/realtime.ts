import { useQueryClient } from "@tanstack/react-query";
import type { QueryClient } from "@tanstack/react-query";
import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useEffectEvent,
  useMemo,
  useState,
  useSyncExternalStore,
} from "react";
import type { ReactNode } from "react";

import {
  createRealtimeManager,
  createRealtimeQueryEffectEngine,
} from "../realtime/index.js";
import type {
  DomainEventV1,
  RealtimeConnectionState,
  RealtimeEventHandler,
  RealtimeManager,
  RealtimeManagerOptions,
  RealtimeQueryClient,
  RealtimeQueryEffectDiagnostic,
  RealtimeQueryEffectRegistry,
  RealtimeSubscribeOptions,
  RealtimeSubscription,
} from "../realtime/index.js";

export type RealtimeManagerFactory = (
  options: RealtimeManagerOptions,
) => RealtimeManager;

interface RealtimeProviderCommonProps {
  readonly autoConnect?: boolean;
  readonly children?: ReactNode;
}

export type RealtimeProviderProps = RealtimeProviderCommonProps &
  (
    | {
        readonly manager: RealtimeManager;
        readonly configuration?: never;
        readonly factory?: never;
      }
    | {
        readonly manager?: never;
        readonly configuration: RealtimeManagerOptions;
        readonly factory?: RealtimeManagerFactory;
      }
  );

interface CreatedRealtimeManager {
  readonly configuration: RealtimeManagerOptions;
  readonly factory: RealtimeManagerFactory;
  readonly manager: RealtimeManager;
}

const RealtimeContext = createContext<RealtimeManager | null>(null);

/**
 * Provides one transport-neutral realtime manager. A supplied manager remains caller-owned;
 * a manager created from configuration is disposed when this provider releases it.
 */
export function RealtimeProvider(props: RealtimeProviderProps): ReactNode {
  const configuredManager = props.manager;
  const configuration = props.configuration;
  const factory = props.factory ?? createRealtimeManager;
  const [created, setCreated] = useState<CreatedRealtimeManager | null>(null);
  const autoConnect = props.autoConnect ?? true;

  useEffect(() => {
    if (configuredManager !== undefined || configuration === undefined) {
      return;
    }
    const manager = factory(configuration);
    setCreated({ configuration, factory, manager });
    return () => {
      manager.dispose();
      setCreated((current) => (current?.manager === manager ? null : current));
    };
  }, [configuration, configuredManager, factory]);

  const createdManager =
    created !== null &&
    created.configuration === configuration &&
    created.factory === factory
      ? created.manager
      : null;
  const manager = configuredManager ?? createdManager;
  useEffect(() => {
    if (autoConnect && manager !== null) {
      manager.connect();
    }
  }, [autoConnect, manager]);

  if (configuredManager === undefined && configuration === undefined) {
    throw new TypeError(
      "RealtimeProvider requires either a manager or manager configuration.",
    );
  }

  if (manager === null) {
    return null;
  }
  return createElement(
    RealtimeContext.Provider,
    { value: manager },
    props.children,
  );
}

/** Returns the manager without subscribing the component to connection or diagnostic changes. */
export function useRealtime(): RealtimeManager {
  const manager = useContext(RealtimeContext);
  if (manager === null) {
    throw new Error("Realtime hooks must be used within RealtimeProvider.");
  }
  return manager;
}

/** Subscribes only to the connection-state primitive, not the manager's broader snapshot. */
export function useConnectionState(): RealtimeConnectionState {
  const manager = useRealtime();
  const subscribe = useCallback(
    (listener: () => void) => manager.subscribeToSnapshot(listener),
    [manager],
  );
  const getSnapshot = useCallback(() => manager.connectionState, [manager]);
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

function useSubscriptionGeneration(manager: RealtimeManager): number {
  const subscribe = useCallback(
    (listener: () => void) => manager.subscribeToSnapshot(listener),
    [manager],
  );
  const getSnapshot = useCallback(
    () => manager.getSnapshot().subscriptionGeneration,
    [manager],
  );
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

export interface UseRealtimeSubscriptionOptions extends RealtimeSubscribeOptions {
  readonly enabled?: boolean;
}

const defaultSubscriptionOptions: UseRealtimeSubscriptionOptions = Object.freeze({});

/**
 * Owns a single manager subscription. Handler changes are observed without changing the stable
 * subscription identity; transport decoding and authorization remain manager responsibilities.
 */
export function useSubscription(
  topic: string,
  handler: RealtimeEventHandler,
  options: UseRealtimeSubscriptionOptions = defaultSubscriptionOptions,
): void {
  const manager = useRealtime();
  const subscriptionGeneration = useSubscriptionGeneration(manager);
  const handleEvent = useEffectEvent((event: DomainEventV1) => {
    handler(event);
  });
  const enabled = options.enabled ?? true;
  const cursor = options.cursor;

  useEffect(() => {
    if (!enabled) {
      return;
    }
    const subscription = manager.subscribe(
      topic,
      handleEvent,
      cursor === undefined ? undefined : { cursor },
    );
    return () => {
      subscription.unsubscribe();
    };
  }, [cursor, enabled, manager, subscriptionGeneration, topic]);
}

/** Semantic event hook; event payloads stay decoder-validated but non-authoritative. */
export function useEvent(
  topic: string,
  handler: RealtimeEventHandler,
  options: UseRealtimeSubscriptionOptions = defaultSubscriptionOptions,
): void {
  useSubscription(topic, handler, options);
}

interface RealtimeQuerySyncCommonOptions {
  /**
   * Registry targets must close over generated `serviceQueryKeys` factories and return the
   * current tenant/principal scope. The hook never constructs operation-name keys.
   */
  readonly registry: RealtimeQueryEffectRegistry;
  readonly revalidateSession: () => void | Promise<void>;
  readonly revalidateCapabilities: () => void | Promise<void>;
  readonly onDiagnostic?: (diagnostic: RealtimeQueryEffectDiagnostic) => void;
  readonly queryClient?: QueryClient;
  readonly cursor?: string;
  readonly enabled?: boolean;
}

export type UseRealtimeQuerySyncOptions = RealtimeQuerySyncCommonOptions &
  (
    | {
        readonly topic: string;
        readonly topics?: never;
      }
    | {
        readonly topic?: never;
        readonly topics: readonly string[];
      }
  );

function createTanStackRealtimeQueryClient(
  queryClient: QueryClient,
): RealtimeQueryClient {
  return Object.freeze({
    invalidateQueries(queryKey: readonly unknown[]) {
      return queryClient.invalidateQueries({ queryKey });
    },
    refetchQueries(queryKey: readonly unknown[]) {
      return queryClient.refetchQueries({ queryKey });
    },
    removeQueries(queryKey: readonly unknown[]) {
      queryClient.removeQueries({ queryKey });
    },
    setQueryData<TData>(
      queryKey: readonly unknown[],
      updater: (current: TData | undefined) => TData | undefined,
    ) {
      queryClient.setQueryData<TData>(queryKey, updater);
    },
  });
}

function canonicalTopics(options: UseRealtimeQuerySyncOptions): readonly string[] {
  const requested =
    options.topic === undefined ? options.topics : [options.topic];
  return [...new Set(requested)].sort();
}

/**
 * Forwards decoder-validated events into the framework-neutral query-effect engine. Effects own
 * all generated-key selection, scope resolution, validation, and conflict policy.
 */
export function useRealtimeQuerySync(
  options: UseRealtimeQuerySyncOptions,
): void {
  const manager = useRealtime();
  const tanStackClient = useQueryClient(options.queryClient);
  const subscriptionGeneration = useSubscriptionGeneration(manager);
  const queryClient = useMemo(
    () => createTanStackRealtimeQueryClient(tanStackClient),
    [tanStackClient],
  );
  const revalidateSession = useEffectEvent(() => options.revalidateSession());
  const revalidateCapabilities = useEffectEvent(() =>
    options.revalidateCapabilities(),
  );
  const diagnose = useEffectEvent((diagnostic: RealtimeQueryEffectDiagnostic) => {
    options.onDiagnostic?.(diagnostic);
  });
  const engine = useMemo(
    () =>
      createRealtimeQueryEffectEngine({
        queryClient,
        registry: options.registry,
        revalidateSession,
        revalidateCapabilities,
        onDiagnostic: diagnose,
      }),
    [options.registry, queryClient],
  );
  const applyEvent = useEffectEvent((event: DomainEventV1) => {
    void engine.apply(event);
  });
  const topicKey = JSON.stringify(canonicalTopics(options));
  const topics = useMemo(() => canonicalTopics(options), [topicKey]);
  const enabled = options.enabled ?? true;
  const cursor = options.cursor;

  useEffect(() => {
    if (!enabled || topics.length === 0) {
      return;
    }
    const subscriptions: RealtimeSubscription[] = [];
    try {
      for (const topic of topics) {
        subscriptions.push(
          manager.subscribe(
            topic,
            applyEvent,
            cursor === undefined ? undefined : { cursor },
          ),
        );
      }
    } catch (error: unknown) {
      for (const subscription of subscriptions) {
        subscription.unsubscribe();
      }
      throw error;
    }

    return () => {
      for (const subscription of subscriptions) {
        subscription.unsubscribe();
      }
    };
  }, [cursor, enabled, manager, subscriptionGeneration, topicKey]);
}
