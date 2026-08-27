import type {
  ClientRealtimeWireMessage,
  DomainEventV1,
  ServerRealtimeWireMessage,
} from "../internal/generated/realtime.js";

export const REALTIME_TRANSPORTS = ["websocket", "sse"] as const;
export type RealtimeTransport = (typeof REALTIME_TRANSPORTS)[number];

export type RealtimeConnectionState =
  | "idle"
  | "connecting"
  | "open"
  | "degraded"
  | "reconnecting"
  | "closed"
  | "unauthorized";

export type RealtimeDisconnectReason =
  | "client-disconnect"
  | "disposed"
  | "identity-transition"
  | "tenant-transition"
  | "protocol-error"
  | "heartbeat-timeout";

export type RealtimeTransportCloseReason =
  | "closed"
  | "network-error"
  | "protocol-error"
  | "heartbeat-timeout"
  | "server-draining"
  | "slow-consumer"
  | "unauthorized";

export type RealtimeDiagnosticCode =
  | "transport-open"
  | "transport-closed"
  | "transport-error"
  | "protocol-error"
  | "message-too-large"
  | "invalid-message"
  | "unknown-message"
  | "duplicate-event"
  | "handler-error"
  | "subscription-revoked"
  | "subscription-error"
  | "command-error"
  | "heartbeat-timeout"
  | "reconnect-scheduled"
  | "reconnect-deferred"
  | "offline"
  | "visibility-hidden"
  | "disposed";

/** Diagnostics deliberately contain no message payloads, URLs, headers, or credentials. */
export interface RealtimeDiagnostic {
  readonly code: RealtimeDiagnosticCode;
  readonly at: number;
  readonly transport: RealtimeTransport;
  readonly attempt?: number;
  readonly delayMs?: number;
  readonly closeCode?: number;
}

export interface RealtimeSnapshot {
  readonly connectionState: RealtimeConnectionState;
  /** The most recent contract-supplied resume cursor. Event ids are never promoted to cursors. */
  readonly lastEventId: string | null;
  /** Changes when an identity or tenant transition revokes all local subscriptions. */
  readonly subscriptionGeneration: number;
  readonly diagnostics: readonly RealtimeDiagnostic[];
}

export type RealtimeEventHandler = (event: DomainEventV1) => void;

export interface RealtimeSubscribeOptions {
  readonly cursor?: string;
}

export interface RealtimeSubscription {
  readonly id: string;
  readonly topic: string;
  unsubscribe(): void;
}

export interface RealtimeCommandOptions {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}

export interface RealtimeTransportSubscription {
  readonly id: string;
  readonly topic: string;
  readonly cursor?: string;
}

export interface RealtimeTransportClose {
  readonly reason: RealtimeTransportCloseReason;
  readonly reconnect: boolean;
  readonly unauthorized?: boolean;
  readonly closeCode?: number;
}

export interface RealtimeTransportDiagnostic {
  readonly code:
    | "transport-error"
    | "protocol-error"
    | "message-too-large"
    | "heartbeat-timeout";
  readonly closeCode?: number;
}

export interface RealtimeTransportConnectOptions {
  readonly cursor?: string;
  readonly signal: AbortSignal;
  readonly subscriptions: readonly RealtimeTransportSubscription[];
  readonly onOpen: () => void;
  readonly onMessage: (message: unknown) => void;
  readonly onClose: (close: RealtimeTransportClose) => void;
  readonly onDegraded: () => void;
  readonly onDiagnostic: (diagnostic: RealtimeTransportDiagnostic) => void;
}

/** Framework-neutral port. Concrete transports own wire I/O; the manager owns policy and retries. */
export interface RealtimeTransportPort {
  readonly kind: RealtimeTransport;
  connect(options: RealtimeTransportConnectOptions): void;
  disconnect(reason?: RealtimeDisconnectReason): void;
  subscribe?(subscription: RealtimeTransportSubscription): Promise<void>;
  unsubscribe?(subscriptionId: string): Promise<void>;
  sendCommand?(
    command: ClientRealtimeWireMessage,
    options?: RealtimeCommandOptions,
  ): Promise<ServerRealtimeWireMessage>;
}

export interface RealtimeClock {
  now(): number;
}

export interface RealtimeTimers {
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface RealtimeOnlinePort {
  getSnapshot(): boolean;
  subscribe(listener: (online: boolean) => void): () => void;
}

export interface RealtimeVisibilityPort {
  getSnapshot(): "visible" | "hidden";
  subscribe(listener: (visibility: "visible" | "hidden") => void): () => void;
}

export interface RealtimeLifecycleContext {
  readonly signal?: AbortSignal;
}

export interface RealtimeManagerOptions {
  readonly transport: RealtimeTransportPort;
  readonly idFactory: () => string;
  readonly clock?: RealtimeClock;
  readonly timers?: RealtimeTimers;
  readonly random?: () => number;
  readonly online?: RealtimeOnlinePort;
  readonly visibility?: RealtimeVisibilityPort;
  readonly maxSubscriptions?: number;
  readonly maxSnapshotListeners?: number;
  readonly maxSeenEventIds?: number;
  readonly maxDiagnostics?: number;
  readonly reconnectBaseDelayMs?: number;
  readonly reconnectMaxDelayMs?: number;
  readonly stableOpenMs?: number;
  /** Exact module-owned event names selected by the assembled browser profile. */
  readonly knownEventTypes?: readonly string[];
  readonly onCompatibilityMessage?: (
    message: unknown,
    reason: "unknown-type" | "unknown-version" | "invalid",
  ) => void;
  readonly onDiagnostic?: (diagnostic: RealtimeDiagnostic) => void;
}

export interface RealtimeManager {
  readonly connectionState: RealtimeConnectionState;
  readonly lastEventId: string | null;
  readonly diagnostics: readonly RealtimeDiagnostic[];
  connect(): void;
  disconnect(reason?: RealtimeDisconnectReason): void;
  dispose(): void;
  subscribe(
    topic: string,
    handler: RealtimeEventHandler,
    options?: RealtimeSubscribeOptions,
  ): RealtimeSubscription;
  unsubscribe(subscriptionId: string): void;
  sendCommand(
    command: ClientRealtimeWireMessage,
    options?: RealtimeCommandOptions,
  ): Promise<ServerRealtimeWireMessage>;
  getSnapshot(): RealtimeSnapshot;
  subscribeToSnapshot(listener: () => void): () => void;
  resetForIdentityTransition(context?: RealtimeLifecycleContext): Promise<void>;
  reestablishForTenant(context?: RealtimeLifecycleContext): Promise<void>;
}
