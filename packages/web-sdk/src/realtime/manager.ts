import {
  decodeRealtimeWireMessage,
  type ClientRealtimeWireMessage,
  type DomainEventV1,
  type ServerRealtimeWireMessage,
  type RealtimeWireMessage,
  type SubscriptionRevokedV1,
} from "../internal/generated/realtime.js";
import {
  abortError,
  defaultClock,
  defaultTimers,
  nonNegativeFinite,
  positiveInteger,
  throwIfAborted,
  validateCursor,
  validateUuidV7,
  validateTopic,
} from "./internals.js";
import type {
  RealtimeCommandOptions,
  RealtimeConnectionState,
  RealtimeDiagnostic,
  RealtimeDisconnectReason,
  RealtimeEventHandler,
  RealtimeLifecycleContext,
  RealtimeManager,
  RealtimeManagerOptions,
  RealtimeOnlinePort,
  RealtimeSnapshot,
  RealtimeSubscribeOptions,
  RealtimeSubscription,
  RealtimeTransportClose,
  RealtimeTransportDiagnostic,
  RealtimeTransportSubscription,
  RealtimeVisibilityPort,
} from "./types.js";

const DEFAULT_MAX_SUBSCRIPTIONS = 256;
const DEFAULT_MAX_SNAPSHOT_LISTENERS = 256;
const DEFAULT_MAX_SEEN_EVENT_IDS = 2_048;
const DEFAULT_MAX_DIAGNOSTICS = 128;
const DEFAULT_RECONNECT_BASE_DELAY_MS = 250;
const DEFAULT_RECONNECT_MAX_DELAY_MS = 30_000;
const DEFAULT_STABLE_OPEN_MS = 10_000;

interface ManagedSubscription extends RealtimeTransportSubscription {
  readonly handler: RealtimeEventHandler;
}

export class RealtimeCommandUnavailableError extends Error {
  constructor() {
    super("The selected realtime transport does not support commands");
    this.name = "RealtimeCommandUnavailableError";
  }
}

export function createRealtimeManager(
  options: RealtimeManagerOptions,
): RealtimeManager {
  return new DefaultRealtimeManager(options);
}

class DefaultRealtimeManager implements RealtimeManager {
  readonly #transport;
  readonly #idFactory;
  readonly #clock;
  readonly #timers;
  readonly #random;
  readonly #online;
  readonly #visibility;
  readonly #maxSubscriptions;
  readonly #maxSnapshotListeners;
  readonly #maxSeenEventIds;
  readonly #maxDiagnostics;
  readonly #reconnectBaseDelayMs;
  readonly #reconnectMaxDelayMs;
  readonly #stableOpenMs;
  readonly #knownEventTypes;
  readonly #onCompatibilityMessage;
  readonly #onDiagnostic;
  readonly #subscriptions = new Map<string, ManagedSubscription>();
  readonly #snapshotListeners = new Set<() => void>();
  readonly #seenEventIds = new Map<string, true>();
  readonly #diagnosticBuffer: RealtimeDiagnostic[] = [];
  readonly #environmentCleanups: Array<() => void> = [];

  #snapshot: RealtimeSnapshot;
  #desiredConnection = false;
  #transportOpen = false;
  #disposed = false;
  #generation = 0;
  #reconnectAttempt = 0;
  #reconnectTimer: unknown;
  #stableTimer: unknown;
  #connectionAbort: AbortController | undefined;
  #environmentSubscribed = false;
  #resubscribingGeneration: number | undefined;

  constructor(options: RealtimeManagerOptions) {
    this.#transport = options.transport;
    this.#idFactory = options.idFactory;
    this.#clock = options.clock ?? defaultClock;
    this.#timers = options.timers ?? defaultTimers;
    this.#random = options.random ?? Math.random;
    this.#online = options.online ?? createBrowserOnlinePort();
    this.#visibility = options.visibility ?? createBrowserVisibilityPort();
    this.#maxSubscriptions = positiveInteger(
      options.maxSubscriptions ?? DEFAULT_MAX_SUBSCRIPTIONS,
      "maxSubscriptions",
    );
    this.#maxSnapshotListeners = positiveInteger(
      options.maxSnapshotListeners ?? DEFAULT_MAX_SNAPSHOT_LISTENERS,
      "maxSnapshotListeners",
    );
    this.#maxSeenEventIds = positiveInteger(
      options.maxSeenEventIds ?? DEFAULT_MAX_SEEN_EVENT_IDS,
      "maxSeenEventIds",
    );
    this.#maxDiagnostics = positiveInteger(
      options.maxDiagnostics ?? DEFAULT_MAX_DIAGNOSTICS,
      "maxDiagnostics",
    );
    this.#reconnectBaseDelayMs = nonNegativeFinite(
      options.reconnectBaseDelayMs ?? DEFAULT_RECONNECT_BASE_DELAY_MS,
      "reconnectBaseDelayMs",
    );
    this.#reconnectMaxDelayMs = nonNegativeFinite(
      options.reconnectMaxDelayMs ?? DEFAULT_RECONNECT_MAX_DELAY_MS,
      "reconnectMaxDelayMs",
    );
    if (this.#reconnectMaxDelayMs < this.#reconnectBaseDelayMs) {
      throw new RangeError(
        "reconnectMaxDelayMs must be greater than or equal to reconnectBaseDelayMs",
      );
    }
    this.#stableOpenMs = nonNegativeFinite(
      options.stableOpenMs ?? DEFAULT_STABLE_OPEN_MS,
      "stableOpenMs",
    );
    this.#knownEventTypes = new Set(options.knownEventTypes ?? []);
    this.#onCompatibilityMessage = options.onCompatibilityMessage;
    this.#onDiagnostic = options.onDiagnostic;
    this.#snapshot = Object.freeze({
      connectionState: "idle",
      lastEventId: null,
      subscriptionGeneration: 0,
      diagnostics: Object.freeze([]),
    });
  }

  get connectionState(): RealtimeConnectionState {
    return this.#snapshot.connectionState;
  }

  get lastEventId(): string | null {
    return this.#snapshot.lastEventId;
  }

  get diagnostics(): readonly RealtimeDiagnostic[] {
    return this.#snapshot.diagnostics;
  }

  connect(): void {
    this.#assertUsable();
    this.#subscribeToEnvironment();
    if (this.#snapshot.connectionState === "unauthorized") {
      return;
    }
    this.#desiredConnection = true;
    if (
      this.#transportOpen ||
      this.#snapshot.connectionState === "connecting" ||
      this.#snapshot.connectionState === "reconnecting" ||
      this.#reconnectTimer !== undefined
    ) {
      return;
    }
    if (this.#online?.getSnapshot() === false) {
      this.#setConnectionState("degraded");
      this.#recordDiagnostic({ code: "offline" });
      return;
    }
    this.#startConnection(this.#snapshot.connectionState !== "idle");
  }

  disconnect(reason: RealtimeDisconnectReason = "client-disconnect"): void {
    if (this.#disposed && reason !== "disposed") {
      return;
    }
    this.#desiredConnection = false;
    this.#stopConnection(reason);
    if (this.#snapshot.connectionState !== "unauthorized") {
      this.#setConnectionState("closed");
    }
  }

  dispose(): void {
    if (this.#disposed) {
      return;
    }
    this.#disposed = true;
    this.#desiredConnection = false;
    this.#stopConnection("disposed");
    for (const cleanup of this.#environmentCleanups.splice(0)) {
      safelyCall(cleanup);
    }
    this.#subscriptions.clear();
    this.#seenEventIds.clear();
    this.#recordDiagnostic({ code: "disposed" });
    this.#setConnectionState("closed");
    this.#snapshotListeners.clear();
  }

  subscribe(
    topic: string,
    handler: RealtimeEventHandler,
    options: RealtimeSubscribeOptions = {},
  ): RealtimeSubscription {
    this.#assertUsable();
    validateTopic(topic);
    if (options.cursor !== undefined) {
      validateCursor(options.cursor);
    }
    if (this.#subscriptions.size >= this.#maxSubscriptions) {
      throw new RangeError("The realtime subscription limit has been reached");
    }
    const id = this.#idFactory();
    validateUuidV7(id, "idFactory result");
    if (this.#subscriptions.has(id)) {
      throw new TypeError("idFactory must return a unique identifier");
    }
    const managed: ManagedSubscription =
      options.cursor === undefined
        ? { id, topic, handler }
        : { id, topic, cursor: options.cursor, handler };
    this.#subscriptions.set(id, managed);
    if (
      this.#transportOpen &&
      this.#resubscribingGeneration !== this.#generation
    ) {
      void this.#syncSubscription(managed, this.#generation);
    }

    let active = true;
    return Object.freeze({
      id,
      topic,
      unsubscribe: () => {
        if (active) {
          active = false;
          this.unsubscribe(id);
        }
      },
    });
  }

  unsubscribe(subscriptionId: string): void {
    const removed = this.#subscriptions.delete(subscriptionId);
    if (!removed || !this.#transportOpen || this.#transport.unsubscribe === undefined) {
      return;
    }
    void this.#transport.unsubscribe(subscriptionId).catch(() => {
      this.#recordDiagnostic({ code: "subscription-error" });
    });
  }

  async sendCommand(
    command: ClientRealtimeWireMessage,
    options?: RealtimeCommandOptions,
  ): Promise<ServerRealtimeWireMessage> {
    this.#assertUsable();
    const decoded = decodeRealtimeWireMessage(command);
    if (!decoded.ok || !isClientWireMessage(decoded.value)) {
      this.#recordDiagnostic({ code: "command-error" });
      throw new TypeError("The outbound command violates the realtime wire contract");
    }
    if (this.#transport.sendCommand === undefined) {
      throw new RealtimeCommandUnavailableError();
    }
    try {
      return await this.#transport.sendCommand(decoded.value, options);
    } catch (error) {
      this.#recordDiagnostic({ code: "command-error" });
      throw error;
    }
  }

  getSnapshot(): RealtimeSnapshot {
    return this.#snapshot;
  }

  subscribeToSnapshot(listener: () => void): () => void {
    this.#assertUsable();
    if (this.#snapshotListeners.size >= this.#maxSnapshotListeners) {
      throw new RangeError("The realtime snapshot listener limit has been reached");
    }
    this.#snapshotListeners.add(listener);
    let active = true;
    return () => {
      if (active) {
        active = false;
        this.#snapshotListeners.delete(listener);
      }
    };
  }

  async resetForIdentityTransition(
    context: RealtimeLifecycleContext = {},
  ): Promise<void> {
    await this.#transitionAuthority("identity-transition", context);
  }

  async reestablishForTenant(
    context: RealtimeLifecycleContext = {},
  ): Promise<void> {
    await this.#transitionAuthority("tenant-transition", context);
  }

  #startConnection(reconnecting: boolean): void {
    if (this.#disposed || !this.#desiredConnection) {
      return;
    }
    if (this.#online?.getSnapshot() === false) {
      this.#setConnectionState("degraded");
      this.#recordDiagnostic({ code: "reconnect-deferred" });
      return;
    }
    this.#clearReconnectTimer();
    this.#clearStableTimer();
    this.#transportOpen = false;
    const generation = ++this.#generation;
    const connectionAbort = new AbortController();
    this.#connectionAbort = connectionAbort;
    this.#setConnectionState(reconnecting ? "reconnecting" : "connecting");
    const cursor = this.#snapshot.lastEventId ?? undefined;
    const subscriptions = Array.from(this.#subscriptions.values(), (subscription) =>
      toTransportSubscription(subscription),
    );
    try {
      this.#transport.connect({
        ...(cursor === undefined ? {} : { cursor }),
        signal: connectionAbort.signal,
        subscriptions,
        onOpen: () => this.#handleOpen(generation),
        onMessage: (message) => this.#handleMessage(generation, message),
        onClose: (close) => this.#handleClose(generation, close),
        onDegraded: () => this.#handleDegraded(generation),
        onDiagnostic: (diagnostic) =>
          this.#handleTransportDiagnostic(generation, diagnostic),
      });
    } catch {
      this.#recordDiagnostic({ code: "transport-error" });
      this.#handleClose(generation, {
        reason: "network-error",
        reconnect: true,
      });
    }
  }

  #handleOpen(generation: number): void {
    if (!this.#isCurrent(generation) || !this.#desiredConnection) {
      return;
    }
    this.#transportOpen = true;
    this.#recordDiagnostic({ code: "transport-open" });
    this.#refreshOpenState();
    if (this.#stableOpenMs === 0) {
      this.#reconnectAttempt = 0;
    } else {
      this.#stableTimer = this.#timers.setTimeout(() => {
        this.#stableTimer = undefined;
        if (this.#isCurrent(generation) && this.#transportOpen) {
          this.#reconnectAttempt = 0;
        }
      }, this.#stableOpenMs);
    }
    void this.#resubscribe(generation);
  }

  #handleMessage(generation: number, input: unknown): void {
    if (!this.#isCurrent(generation) || !this.#transportOpen) {
      return;
    }
    const decoded = decodeRealtimeWireMessage(input, this.#knownEventTypes);
    if (!decoded.ok) {
      this.#recordDiagnostic({
        code: decoded.reason === "invalid" ? "invalid-message" : "unknown-message",
      });
      if (this.#onCompatibilityMessage !== undefined) {
        safelyCall(() => this.#onCompatibilityMessage?.(input, decoded.reason));
      }
      return;
    }

    const message = decoded.value;
    if (isClientWireMessage(message)) {
      this.#recordDiagnostic({ code: "protocol-error" });
      if (this.#onCompatibilityMessage !== undefined) {
        safelyCall(() => this.#onCompatibilityMessage?.(input, "invalid"));
      }
      return;
    }
    if (isSubscriptionRevoked(message)) {
      this.#handleRevocation(message);
      return;
    }
    if (isServerControlMessage(message)) {
      return;
    }
    if (isDomainEvent(message)) {
      this.#dispatchDomainEvent(message);
    }
  }

  #dispatchDomainEvent(event: DomainEventV1): void {
    const subscription = this.#subscriptions.get(
      event.payload.subscription_id,
    );
    if (subscription === undefined || subscription.topic !== event.payload.topic) {
      this.#recordDiagnostic({ code: "protocol-error" });
      return;
    }
    if (this.#seenEventIds.has(event.id)) {
      this.#recordDiagnostic({ code: "duplicate-event" });
      return;
    }
    this.#seenEventIds.set(event.id, true);
    if (this.#seenEventIds.size > this.#maxSeenEventIds) {
      const oldestId = this.#seenEventIds.keys().next().value as string | undefined;
      if (oldestId !== undefined) {
        this.#seenEventIds.delete(oldestId);
      }
    }

    const cursor = event.payload.cursor;
    if (cursor !== null) {
      this.#subscriptions.set(subscription.id, {
        ...subscription,
        cursor,
      });
      this.#updateSnapshot({ lastEventId: cursor });
    }
    this.#callEventHandler(subscription.handler, event);
  }

  #handleRevocation(message: SubscriptionRevokedV1): void {
    this.#subscriptions.delete(message.payload.subscription_id);
    this.#recordDiagnostic({ code: "subscription-revoked" });
    if (message.payload.reason === "identity_revoked") {
      this.#desiredConnection = false;
      this.#stopConnection("identity-transition");
      this.#subscriptions.clear();
      this.#setConnectionState("unauthorized");
    }
  }

  #callEventHandler(handler: RealtimeEventHandler, event: DomainEventV1): void {
    try {
      handler(event);
    } catch {
      this.#recordDiagnostic({ code: "handler-error" });
    }
  }

  #handleClose(generation: number, close: RealtimeTransportClose): void {
    if (!this.#isCurrent(generation)) {
      return;
    }
    this.#transportOpen = false;
    this.#connectionAbort = undefined;
    this.#clearStableTimer();
    this.#recordDiagnostic({
      code: "transport-closed",
      ...(close.closeCode === undefined ? {} : { closeCode: close.closeCode }),
    });
    if (close.unauthorized === true || close.reason === "unauthorized") {
      this.#desiredConnection = false;
      this.#clearReconnectTimer();
      this.#setConnectionState("unauthorized");
      return;
    }
    if (!this.#desiredConnection || !close.reconnect) {
      this.#setConnectionState("closed");
      return;
    }
    this.#scheduleReconnect();
  }

  #handleDegraded(generation: number): void {
    if (this.#isCurrent(generation) && this.#desiredConnection) {
      this.#setConnectionState("degraded");
    }
  }

  #handleTransportDiagnostic(
    generation: number,
    diagnostic: RealtimeTransportDiagnostic,
  ): void {
    if (!this.#isCurrent(generation)) {
      return;
    }
    this.#recordDiagnostic({
      code: diagnostic.code,
      ...(diagnostic.closeCode === undefined
        ? {}
        : { closeCode: diagnostic.closeCode }),
    });
  }

  #scheduleReconnect(): void {
    if (this.#reconnectTimer !== undefined || !this.#desiredConnection) {
      return;
    }
    if (this.#online?.getSnapshot() === false) {
      this.#setConnectionState("degraded");
      this.#recordDiagnostic({ code: "reconnect-deferred" });
      return;
    }
    const attempt = this.#reconnectAttempt;
    this.#reconnectAttempt = Math.min(attempt + 1, 31);
    const exponentialDelay =
      this.#reconnectBaseDelayMs * 2 ** Math.min(attempt, 30);
    const bound = Math.min(this.#reconnectMaxDelayMs, exponentialDelay);
    const randomValue = this.#random();
    const normalizedRandom = Number.isFinite(randomValue)
      ? Math.min(0.999_999_999_999_999_9, Math.max(0, randomValue))
      : 0;
    const delayMs = Math.floor(normalizedRandom * bound);
    this.#setConnectionState("reconnecting");
    this.#recordDiagnostic({
      code: "reconnect-scheduled",
      attempt,
      delayMs,
    });
    this.#reconnectTimer = this.#timers.setTimeout(() => {
      this.#reconnectTimer = undefined;
      if (this.#desiredConnection && !this.#transportOpen) {
        this.#startConnection(true);
      }
    }, delayMs);
  }

  async #resubscribe(generation: number): Promise<void> {
    if (
      this.#transport.subscribe === undefined ||
      this.#resubscribingGeneration === generation
    ) {
      return;
    }
    this.#resubscribingGeneration = generation;
    try {
      for (const subscription of this.#subscriptions.values()) {
        if (!this.#isCurrent(generation) || !this.#transportOpen) {
          return;
        }
        await this.#syncSubscription(subscription, generation);
      }
    } finally {
      if (this.#resubscribingGeneration === generation) {
        this.#resubscribingGeneration = undefined;
      }
    }
  }

  async #syncSubscription(
    subscription: ManagedSubscription,
    generation: number,
  ): Promise<void> {
    if (
      this.#transport.subscribe === undefined ||
      !this.#isCurrent(generation) ||
      !this.#transportOpen ||
      !this.#subscriptions.has(subscription.id)
    ) {
      return;
    }
    try {
      await this.#transport.subscribe(toTransportSubscription(subscription));
    } catch {
      if (this.#isCurrent(generation)) {
        this.#recordDiagnostic({ code: "subscription-error" });
      }
    }
  }

  #handleOnlineChange(online: boolean): void {
    if (this.#disposed || !this.#desiredConnection) {
      return;
    }
    if (!online) {
      this.#clearReconnectTimer();
      this.#setConnectionState("degraded");
      this.#recordDiagnostic({ code: "offline" });
      return;
    }
    if (this.#transportOpen) {
      this.#refreshOpenState();
    } else {
      this.#accelerateReconnect();
    }
  }

  #handleVisibilityChange(visibility: "visible" | "hidden"): void {
    if (this.#disposed || !this.#desiredConnection) {
      return;
    }
    if (visibility === "hidden") {
      if (this.#transportOpen) {
        this.#setConnectionState("degraded");
      }
      this.#recordDiagnostic({ code: "visibility-hidden" });
      return;
    }
    if (this.#transportOpen) {
      this.#refreshOpenState();
    } else if (this.#online?.getSnapshot() !== false) {
      this.#accelerateReconnect();
    }
  }

  #accelerateReconnect(): void {
    if (
      !this.#desiredConnection ||
      this.#transportOpen ||
      this.#connectionAbort !== undefined
    ) {
      return;
    }
    this.#clearReconnectTimer();
    this.#startConnection(true);
  }

  #refreshOpenState(): void {
    const degraded =
      this.#online?.getSnapshot() === false ||
      this.#visibility?.getSnapshot() === "hidden";
    this.#setConnectionState(degraded ? "degraded" : "open");
  }

  #stopConnection(reason: RealtimeDisconnectReason): void {
    this.#generation += 1;
    this.#clearReconnectTimer();
    this.#clearStableTimer();
    this.#connectionAbort?.abort(abortError());
    this.#connectionAbort = undefined;
    this.#transportOpen = false;
    this.#resubscribingGeneration = undefined;
    try {
      this.#transport.disconnect(reason);
    } catch {
      this.#recordDiagnostic({ code: "transport-error" });
    }
  }

  async #transitionAuthority(
    reason: "identity-transition" | "tenant-transition",
    context: RealtimeLifecycleContext,
  ): Promise<void> {
    throwIfAborted(context.signal);
    const shouldReconnect =
      this.#desiredConnection && this.#snapshot.connectionState !== "unauthorized";
    this.#desiredConnection = false;
    this.#stopConnection(reason);
    this.#clearAuthorityBoundState();
    this.#setConnectionState("idle");
    await Promise.resolve();
    throwIfAborted(context.signal);
    if (shouldReconnect) {
      this.#desiredConnection = true;
      this.connect();
    }
  }

  #clearAuthorityBoundState(): void {
    this.#subscriptions.clear();
    this.#seenEventIds.clear();
    this.#reconnectAttempt = 0;
    this.#updateSnapshot({
      lastEventId: null,
      subscriptionGeneration: this.#snapshot.subscriptionGeneration + 1,
    });
  }

  #clearReconnectTimer(): void {
    if (this.#reconnectTimer !== undefined) {
      this.#timers.clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = undefined;
    }
  }

  #clearStableTimer(): void {
    if (this.#stableTimer !== undefined) {
      this.#timers.clearTimeout(this.#stableTimer);
      this.#stableTimer = undefined;
    }
  }

  #recordDiagnostic(
    diagnostic: Omit<RealtimeDiagnostic, "at" | "transport">,
  ): void {
    const entry: RealtimeDiagnostic = Object.freeze({
      ...diagnostic,
      at: this.#clock.now(),
      transport: this.#transport.kind,
    });
    this.#diagnosticBuffer.push(entry);
    if (this.#diagnosticBuffer.length > this.#maxDiagnostics) {
      this.#diagnosticBuffer.splice(
        0,
        this.#diagnosticBuffer.length - this.#maxDiagnostics,
      );
    }
    this.#updateSnapshot({
      diagnostics: Object.freeze(this.#diagnosticBuffer.slice()),
    });
    if (this.#onDiagnostic !== undefined) {
      safelyCall(() => this.#onDiagnostic?.(entry));
    }
  }

  #subscribeToEnvironment(): void {
    if (this.#environmentSubscribed) {
      return;
    }
    this.#environmentSubscribed = true;
    if (this.#online !== undefined) {
      this.#environmentCleanups.push(
        this.#online.subscribe((online) => this.#handleOnlineChange(online)),
      );
    }
    if (this.#visibility !== undefined) {
      this.#environmentCleanups.push(
        this.#visibility.subscribe((visibility) =>
          this.#handleVisibilityChange(visibility),
        ),
      );
    }
  }

  #setConnectionState(connectionState: RealtimeConnectionState): void {
    if (this.#snapshot.connectionState !== connectionState) {
      this.#updateSnapshot({ connectionState });
    }
  }

  #updateSnapshot(update: Partial<RealtimeSnapshot>): void {
    this.#snapshot = Object.freeze({
      connectionState:
        update.connectionState ?? this.#snapshot.connectionState,
      lastEventId:
        update.lastEventId === undefined
          ? this.#snapshot.lastEventId
          : update.lastEventId,
      subscriptionGeneration:
        update.subscriptionGeneration ?? this.#snapshot.subscriptionGeneration,
      diagnostics: update.diagnostics ?? this.#snapshot.diagnostics,
    });
    for (const listener of Array.from(this.#snapshotListeners)) {
      safelyCall(listener);
    }
  }

  #isCurrent(generation: number): boolean {
    return !this.#disposed && generation === this.#generation;
  }

  #assertUsable(): void {
    if (this.#disposed) {
      throw new Error("The realtime manager has been disposed");
    }
  }
}

function toTransportSubscription(
  subscription: ManagedSubscription,
): RealtimeTransportSubscription {
  return subscription.cursor === undefined
    ? { id: subscription.id, topic: subscription.topic }
    : {
        id: subscription.id,
        topic: subscription.topic,
        cursor: subscription.cursor,
      };
}
function isClientWireMessage(
  message: RealtimeWireMessage,
): message is ClientRealtimeWireMessage {
  return (
    message.type === "subscription.create" ||
    message.type === "subscription.delete" ||
    message.type === "ping"
  );
}

function isSubscriptionRevoked(
  message: ServerRealtimeWireMessage,
): message is SubscriptionRevokedV1 {
  return (
    message.type === "subscription.revoked" &&
    "reason" in message.payload &&
    "subscription_id" in message.payload
  );
}

function isServerControlMessage(message: ServerRealtimeWireMessage): boolean {
  return (
    message.type === "subscription.created" ||
    message.type === "subscription.deleted" ||
    message.type === "command.rejected" ||
    message.type === "pong"
  );
}

function isDomainEvent(
  message: ServerRealtimeWireMessage,
): message is DomainEventV1 {
  return (
    message.type !== "subscription.created" &&
    message.type !== "subscription.deleted" &&
    message.type !== "command.rejected" &&
    message.type !== "pong" &&
    message.type !== "subscription.revoked" &&
    "topic" in message.payload &&
    "cursor" in message.payload &&
    "data" in message.payload
  );
}


function safelyCall(callback: () => void): void {
  try {
    callback();
  } catch {
    // User callbacks are intentionally isolated from manager and transport state.
  }
}

function createBrowserOnlinePort(): RealtimeOnlinePort | undefined {
  if (
    typeof globalThis.addEventListener !== "function" ||
    typeof globalThis.navigator === "undefined"
  ) {
    return undefined;
  }
  return {
    getSnapshot: () => globalThis.navigator.onLine,
    subscribe: (listener) => {
      const online = () => listener(true);
      const offline = () => listener(false);
      globalThis.addEventListener("online", online);
      globalThis.addEventListener("offline", offline);
      return () => {
        globalThis.removeEventListener("online", online);
        globalThis.removeEventListener("offline", offline);
      };
    },
  };
}

function createBrowserVisibilityPort(): RealtimeVisibilityPort | undefined {
  if (typeof globalThis.document === "undefined") {
    return undefined;
  }
  return {
    getSnapshot: () =>
      globalThis.document.visibilityState === "hidden" ? "hidden" : "visible",
    subscribe: (listener) => {
      const changed = () => {
        listener(
          globalThis.document.visibilityState === "hidden" ? "hidden" : "visible",
        );
      };
      globalThis.document.addEventListener("visibilitychange", changed);
      return () => {
        globalThis.document.removeEventListener("visibilitychange", changed);
      };
    },
  };
}
