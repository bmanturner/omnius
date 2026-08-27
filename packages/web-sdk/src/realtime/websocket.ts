import {
  decodeRealtimeWireMessage,
  type ClientRealtimeWireMessage,
  type PingV1,
  type ServerRealtimeWireMessage,
  type RealtimeWireMessage,
  type CommandRejectedV1,
  type PongV1,
  type SubscriptionCreatedV1,
  type SubscriptionDeletedV1,
  type SubscriptionCreateV1,
  type SubscriptionDeleteV1,
} from "../internal/generated/realtime.js";
import {
  abortError,
  defaultClock,
  defaultTimers,
  isSameOrigin,
  nonNegativeFinite,
  positiveInteger,
  resolveWebSocketUrl,
  utf8ByteLength,
} from "./internals.js";
import type {
  RealtimeClock,
  RealtimeCommandOptions,
  RealtimeDisconnectReason,
  RealtimeTimers,
  RealtimeTransportConnectOptions,
  RealtimeTransportClose,
  RealtimeTransportPort,
  RealtimeTransportSubscription,
} from "./types.js";

export const REALTIME_WEBSOCKET_PROTOCOL = "omnius.realtime.v1";

const DEFAULT_WEBSOCKET_PATH = "/realtime/ws";
const DEFAULT_MAX_MESSAGE_SIZE_BYTES = 256 * 1024;
const DEFAULT_MAX_PENDING_COMMANDS = 64;
const DEFAULT_COMMAND_TIMEOUT_MS = 10_000;
const DEFAULT_HEARTBEAT_INTERVAL_MS = 20_000;
const DEFAULT_IDLE_TIMEOUT_MS = 60_000;
const OPEN_READY_STATE = 1;

type CommandRejectionCode =
  | "unauthorized"
  | "connection_not_active"
  | "not_found"
  | "conflict"
  | "capacity_exceeded"
  | "unavailable";

export interface RealtimeWebSocketLike {
  binaryType: BinaryType;
  readonly readyState: number;
  readonly protocol: string;
  onopen: ((event: Event) => unknown) | null;
  onmessage: ((event: MessageEvent<unknown>) => unknown) | null;
  onerror: ((event: Event) => unknown) | null;
  onclose: ((event: CloseEvent) => unknown) | null;
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

export interface RealtimeWebSocketCredentialResult {
  readonly url: string | URL;
  readonly protocols?: readonly string[];
}

/**
 * Explicit escape hatch for an application-approved URL or subprotocol credential scheme.
 * Neither inputs nor outputs from this strategy are ever included in diagnostics.
 */
export type RealtimeWebSocketCredentialStrategy = (input: {
  readonly url: URL;
  readonly protocols: readonly string[];
}) => RealtimeWebSocketCredentialResult;

export interface RealtimeWebSocketTransportOptions {
  readonly idFactory: () => string;
  readonly url?: string | URL;
  readonly baseUrl?: string | URL;
  readonly webSocketFactory?: (
    url: string,
    protocols: readonly string[],
  ) => RealtimeWebSocketLike;
  readonly credentialStrategy?: RealtimeWebSocketCredentialStrategy;
  readonly maxMessageSizeBytes?: number;
  readonly maxPendingCommands?: number;
  readonly commandTimeoutMs?: number;
  readonly heartbeatIntervalMs?: number;
  readonly idleTimeoutMs?: number;
  readonly unauthorizedCloseCodes?: readonly number[];
  readonly drainCloseCodes?: readonly number[];
  readonly clock?: RealtimeClock;
  readonly timers?: RealtimeTimers;
}

export class RealtimeCommandRejectedError extends Error {
  readonly code: CommandRejectionCode;

  constructor(code: CommandRejectionCode) {
    super(`The realtime command was rejected (${code})`);
    this.name = "RealtimeCommandRejectedError";
    this.code = code;
  }
}

export class RealtimeCommandTimeoutError extends Error {
  constructor() {
    super("The realtime command timed out");
    this.name = "RealtimeCommandTimeoutError";
  }
}

export class RealtimeCommandCapacityError extends Error {
  constructor() {
    super("The realtime command capacity has been reached");
    this.name = "RealtimeCommandCapacityError";
  }
}

export class RealtimeWebSocketNotOpenError extends Error {
  constructor() {
    super("The realtime WebSocket is not open");
    this.name = "RealtimeWebSocketNotOpenError";
  }
}

export function createWebSocketTransport(
  options: RealtimeWebSocketTransportOptions,
): RealtimeTransportPort {
  return new WebSocketRealtimeTransport(options);
}

interface PendingCommand {
  readonly resolve: (message: ServerRealtimeWireMessage) => void;
  readonly reject: (error: unknown) => void;
  readonly timeoutHandle: unknown;
  readonly signal?: AbortSignal;
  readonly abortListener?: () => void;
}

class WebSocketRealtimeTransport implements RealtimeTransportPort {
  readonly kind = "websocket" as const;
  readonly #idFactory;
  readonly #configuredUrl;
  readonly #baseUrl;
  readonly #webSocketFactory;
  readonly #credentialStrategy;
  readonly #maxMessageSizeBytes;
  readonly #maxPendingCommands;
  readonly #commandTimeoutMs;
  readonly #heartbeatIntervalMs;
  readonly #idleTimeoutMs;
  readonly #unauthorizedCloseCodes;
  readonly #drainCloseCodes;
  readonly #clock;
  readonly #timers;
  readonly #pendingCommands = new Map<string, PendingCommand>();

  #socket: RealtimeWebSocketLike | undefined;
  #callbacks: RealtimeTransportConnectOptions | undefined;
  #abortCleanup: (() => void) | undefined;
  #heartbeatTimer: unknown;
  #lastActivityAt = 0;
  #heartbeatInFlight = false;
  #ended = true;

  constructor(options: RealtimeWebSocketTransportOptions) {
    this.#idFactory = options.idFactory;
    this.#configuredUrl = options.url;
    this.#baseUrl = options.baseUrl;
    this.#webSocketFactory = options.webSocketFactory ?? defaultWebSocketFactory;
    this.#credentialStrategy = options.credentialStrategy;
    this.#maxMessageSizeBytes = positiveInteger(
      options.maxMessageSizeBytes ?? DEFAULT_MAX_MESSAGE_SIZE_BYTES,
      "maxMessageSizeBytes",
    );
    this.#maxPendingCommands = positiveInteger(
      options.maxPendingCommands ?? DEFAULT_MAX_PENDING_COMMANDS,
      "maxPendingCommands",
    );
    this.#commandTimeoutMs = nonNegativeFinite(
      options.commandTimeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS,
      "commandTimeoutMs",
    );
    this.#heartbeatIntervalMs = positiveInteger(
      options.heartbeatIntervalMs ?? DEFAULT_HEARTBEAT_INTERVAL_MS,
      "heartbeatIntervalMs",
    );
    this.#idleTimeoutMs = positiveInteger(
      options.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS,
      "idleTimeoutMs",
    );
    if (this.#idleTimeoutMs <= this.#heartbeatIntervalMs) {
      throw new RangeError("idleTimeoutMs must be greater than heartbeatIntervalMs");
    }
    this.#unauthorizedCloseCodes = boundedCodeSet(
      options.unauthorizedCloseCodes ?? [4401, 4403],
      "unauthorizedCloseCodes",
    );
    this.#drainCloseCodes = boundedCodeSet(
      options.drainCloseCodes ?? [1012],
      "drainCloseCodes",
    );
    this.#clock = options.clock ?? defaultClock;
    this.#timers = options.timers ?? defaultTimers;
  }

  connect(callbacks: RealtimeTransportConnectOptions): void {
    this.disconnect("client-disconnect");
    const { base, url: initialUrl } = resolveWebSocketUrl(
      this.#configuredUrl,
      DEFAULT_WEBSOCKET_PATH,
      this.#baseUrl,
    );
    let url = initialUrl;
    let protocols: readonly string[] = [REALTIME_WEBSOCKET_PROTOCOL];
    if (this.#credentialStrategy === undefined) {
      if (
        !isSameOrigin(base, url) ||
        url.username.length !== 0 ||
        url.password.length !== 0
      ) {
        throw new TypeError(
          "Ambient-cookie WebSockets must be same-origin and contain no URL credentials",
        );
      }
    } else {
      const credential = this.#credentialStrategy({
        url: new URL(url.toString()),
        protocols,
      });
      const resolved = resolveWebSocketUrl(
        credential.url,
        DEFAULT_WEBSOCKET_PATH,
        base,
      );
      url = resolved.url;
      protocols = credential.protocols ?? protocols;
    }
    protocols = validateProtocols(protocols);

    const socket = this.#webSocketFactory(url.toString(), protocols);
    socket.binaryType = "arraybuffer";
    this.#socket = socket;
    this.#callbacks = callbacks;
    this.#ended = false;
    this.#lastActivityAt = this.#clock.now();

    const abortListener = () => this.disconnect("client-disconnect");
    callbacks.signal.addEventListener("abort", abortListener, { once: true });
    this.#abortCleanup = () => {
      callbacks.signal.removeEventListener("abort", abortListener);
    };

    socket.onopen = () => {
      if (!this.#isActive(socket)) {
        return;
      }
      if (socket.protocol !== REALTIME_WEBSOCKET_PROTOCOL) {
        callbacks.onDiagnostic({ code: "protocol-error" });
        this.#finish(socket, {
          reason: "protocol-error",
          reconnect: false,
          closeCode: 1002,
        });
        safelyCloseSocket(socket, 1002, "protocol-error");
        return;
      }
      this.#lastActivityAt = this.#clock.now();
      callbacks.onOpen();
      this.#scheduleHeartbeat(socket);
    };
    socket.onmessage = (event) => {
      if (this.#isActive(socket)) {
        void this.#handleMessage(socket, event.data);
      }
    };
    socket.onerror = () => {
      if (this.#isActive(socket)) {
        callbacks.onDiagnostic({ code: "transport-error" });
        callbacks.onDegraded();
      }
    };
    socket.onclose = (event) => {
      callbacks.signal.removeEventListener("abort", abortListener);
      if (!this.#isActive(socket)) {
        return;
      }
      const unauthorized = this.#unauthorizedCloseCodes.has(event.code);
      const draining = this.#drainCloseCodes.has(event.code);
      this.#finish(socket, {
        reason: unauthorized
          ? "unauthorized"
          : draining
            ? "server-draining"
            : "network-error",
        reconnect: !unauthorized,
        ...(unauthorized ? { unauthorized: true } : {}),
        closeCode: event.code,
      });
    };
  }

  disconnect(reason: RealtimeDisconnectReason = "client-disconnect"): void {
    const socket = this.#socket;
    this.#socket = undefined;
    this.#callbacks = undefined;
    this.#ended = true;
    this.#clearHeartbeat();
    this.#rejectAllPending(abortError());
    if (socket !== undefined) {
      socket.onopen = null;
      socket.onmessage = null;
      socket.onerror = null;
      socket.onclose = null;
      safelyCloseSocket(socket, 1000, reason);
    }
    this.#abortCleanup?.();
    this.#abortCleanup = undefined;
  }

  async subscribe(subscription: RealtimeTransportSubscription): Promise<void> {
    const message: SubscriptionCreateV1 = {
      v: 1,
      id: this.#idFactory(),
      type: "subscription.create",
      correlation_id: null,
      payload:
        subscription.cursor === undefined
          ? {
              subscription_id: subscription.id,
              topic: subscription.topic,
            }
          : {
              subscription_id: subscription.id,
              topic: subscription.topic,
              cursor: subscription.cursor,
            },
    };
    const response = await this.sendCommand(message);
    if (
      !isSubscriptionCreatedResponse(response) ||
      response.payload.subscription_id !== subscription.id ||
      response.payload.topic !== subscription.topic
    ) {
      throw new Error("The subscription acknowledgement did not match the request");
    }
  }

  async unsubscribe(subscriptionId: string): Promise<void> {
    const message: SubscriptionDeleteV1 = {
      v: 1,
      id: this.#idFactory(),
      type: "subscription.delete",
      correlation_id: null,
      payload: { subscription_id: subscriptionId },
    };
    const response = await this.sendCommand(message);
    if (
      !isSubscriptionDeletedResponse(response) ||
      response.payload.subscription_id !== subscriptionId
    ) {
      throw new Error("The subscription deletion acknowledgement did not match the request");
    }
  }

  sendCommand(
    command: ClientRealtimeWireMessage,
    options: RealtimeCommandOptions = {},
  ): Promise<ServerRealtimeWireMessage> {
    const decodedCommand = decodeRealtimeWireMessage(command);
    if (!decodedCommand.ok || !isClientCommand(decodedCommand.value)) {
      return Promise.reject(
        new TypeError("The outbound realtime command violates the wire contract"),
      );
    }
    const validatedCommand = decodedCommand.value;
    const socket = this.#socket;
    if (
      socket === undefined ||
      socket.readyState !== OPEN_READY_STATE ||
      this.#ended
    ) {
      return Promise.reject(new RealtimeWebSocketNotOpenError());
    }
    if (options.signal?.aborted === true) {
      return Promise.reject(options.signal.reason ?? abortError());
    }
    if (this.#pendingCommands.size >= this.#maxPendingCommands) {
      return Promise.reject(new RealtimeCommandCapacityError());
    }
    const timeoutMs = nonNegativeFinite(
      options.timeoutMs ?? this.#commandTimeoutMs,
      "timeoutMs",
    );
    const commandId = validatedCommand.id;
    if (this.#pendingCommands.has(commandId)) {
      return Promise.reject(
        new TypeError("A command with this id is already pending"),
      );
    }
    let serialized: string;
    try {
      serialized = JSON.stringify(validatedCommand);
    } catch (error) {
      return Promise.reject(error);
    }
    if (utf8ByteLength(serialized) > this.#maxMessageSizeBytes) {
      return Promise.reject(new RangeError("The realtime command is too large"));
    }

    return new Promise<ServerRealtimeWireMessage>((resolve, reject) => {
      const timeoutHandle = this.#timers.setTimeout(() => {
        const pending = this.#takePending(commandId);
        pending?.reject(new RealtimeCommandTimeoutError());
      }, timeoutMs);
      const abortListener =
        options.signal === undefined
          ? undefined
          : () => {
              const pending = this.#takePending(commandId);
              pending?.reject(options.signal?.reason ?? abortError());
            };
      const pending: PendingCommand = {
        resolve,
        reject,
        timeoutHandle,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        ...(abortListener === undefined ? {} : { abortListener }),
      };
      this.#pendingCommands.set(commandId, pending);
      if (options.signal !== undefined && abortListener !== undefined) {
        options.signal.addEventListener("abort", abortListener, { once: true });
      }
      try {
        socket.send(serialized);
      } catch (error) {
        this.#takePending(commandId)?.reject(error);
      }
    });
  }

  async #handleMessage(
    socket: RealtimeWebSocketLike,
    data: unknown,
  ): Promise<void> {
    const callbacks = this.#callbacks;
    if (callbacks === undefined || !this.#isActive(socket)) {
      return;
    }
    const text = await this.#readBoundedMessage(data);
    if (text === undefined || !this.#isActive(socket)) {
      return;
    }
    this.#lastActivityAt = this.#clock.now();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      callbacks.onMessage(text);
      return;
    }

    const decoded = decodeRealtimeWireMessage(parsed);
    if (decoded.ok && isServerMessage(decoded.value) && isCorrelatedResponse(decoded.value)) {
      const pending = this.#takePending(decoded.value.correlation_id);
      if (pending !== undefined) {
        if (decoded.value.type === "command.rejected") {
          pending.reject(
            new RealtimeCommandRejectedError(decoded.value.payload.code),
          );
        } else {
          pending.resolve(decoded.value);
        }
      }
    }
    callbacks.onMessage(parsed);
  }

  async #readBoundedMessage(data: unknown): Promise<string | undefined> {
    const callbacks = this.#callbacks;
    if (callbacks === undefined) {
      return undefined;
    }
    if (typeof data === "string") {
      if (utf8ByteLength(data) <= this.#maxMessageSizeBytes) {
        return data;
      }
    } else if (data instanceof ArrayBuffer) {
      if (data.byteLength <= this.#maxMessageSizeBytes) {
        return new TextDecoder().decode(data);
      }
    } else if (ArrayBuffer.isView(data)) {
      if (data.byteLength <= this.#maxMessageSizeBytes) {
        return new TextDecoder().decode(data);
      }
    } else if (typeof Blob !== "undefined" && data instanceof Blob) {
      if (data.size <= this.#maxMessageSizeBytes) {
        return await data.text();
      }
    } else {
      callbacks.onMessage(data);
      return undefined;
    }
    callbacks.onDiagnostic({ code: "message-too-large" });
    const socket = this.#socket;
    if (socket !== undefined) {
      this.#finish(socket, {
        reason: "protocol-error",
        reconnect: false,
        closeCode: 1009,
      });
      safelyCloseSocket(socket, 1009, "message-too-large");
    }
    return undefined;
  }

  #scheduleHeartbeat(socket: RealtimeWebSocketLike): void {
    this.#clearHeartbeat();
    this.#heartbeatTimer = this.#timers.setTimeout(() => {
      this.#heartbeatTimer = undefined;
      if (!this.#isActive(socket) || socket.readyState !== OPEN_READY_STATE) {
        return;
      }
      const idleFor = Math.max(0, this.#clock.now() - this.#lastActivityAt);
      if (idleFor >= this.#idleTimeoutMs) {
        this.#callbacks?.onDiagnostic({ code: "heartbeat-timeout" });
        this.#finish(socket, {
          reason: "heartbeat-timeout",
          reconnect: true,
          closeCode: 4000,
        });
        safelyCloseSocket(socket, 4000, "heartbeat-timeout");
        return;
      }
      if (idleFor >= this.#heartbeatIntervalMs && !this.#heartbeatInFlight) {
        this.#heartbeatInFlight = true;
        const ping: PingV1 = {
          v: 1,
          id: this.#idFactory(),
          type: "ping",
          correlation_id: null,
          payload: {},
        };
        void this.sendCommand(ping, {
          timeoutMs: this.#idleTimeoutMs - idleFor,
        })
          .catch(() => {
            if (this.#isActive(socket)) {
              this.#callbacks?.onDiagnostic({ code: "heartbeat-timeout" });
              this.#finish(socket, {
                reason: "heartbeat-timeout",
                reconnect: true,
                closeCode: 4000,
              });
              safelyCloseSocket(socket, 4000, "heartbeat-timeout");
            }
          })
          .finally(() => {
            this.#heartbeatInFlight = false;
          });
      }
      this.#scheduleHeartbeat(socket);
    }, this.#heartbeatIntervalMs);
  }

  #finish(
    socket: RealtimeWebSocketLike,
    close: RealtimeTransportClose,
  ): void {
    if (!this.#isActive(socket)) {
      return;
    }
    const callbacks = this.#callbacks;
    this.#ended = true;
    this.#socket = undefined;
    this.#callbacks = undefined;
    this.#abortCleanup?.();
    this.#abortCleanup = undefined;
    socket.onopen = null;
    socket.onmessage = null;
    socket.onerror = null;
    socket.onclose = null;
    this.#clearHeartbeat();
    this.#rejectAllPending(new RealtimeWebSocketNotOpenError());
    callbacks?.onClose(close);
  }

  #takePending(correlationId: string): PendingCommand | undefined {
    const pending = this.#pendingCommands.get(correlationId);
    if (pending === undefined) {
      return undefined;
    }
    this.#pendingCommands.delete(correlationId);
    this.#timers.clearTimeout(pending.timeoutHandle);
    if (pending.signal !== undefined && pending.abortListener !== undefined) {
      pending.signal.removeEventListener("abort", pending.abortListener);
    }
    return pending;
  }

  #rejectAllPending(error: unknown): void {
    for (const correlationId of Array.from(this.#pendingCommands.keys())) {
      this.#takePending(correlationId)?.reject(error);
    }
  }

  #clearHeartbeat(): void {
    if (this.#heartbeatTimer !== undefined) {
      this.#timers.clearTimeout(this.#heartbeatTimer);
      this.#heartbeatTimer = undefined;
    }
    this.#heartbeatInFlight = false;
  }

  #isActive(socket: RealtimeWebSocketLike): boolean {
    return !this.#ended && socket === this.#socket;
  }
}

function isClientCommand(
  message: RealtimeWireMessage,
): message is ClientRealtimeWireMessage {
  return (
    message.type === "subscription.create" ||
    message.type === "subscription.delete" ||
    message.type === "ping"
  );
}

function isSubscriptionCreatedResponse(
  message: ServerRealtimeWireMessage,
): message is SubscriptionCreatedV1 {
  return (
    message.type === "subscription.created" &&
    "subscription_id" in message.payload &&
    "topic" in message.payload
  );
}

function isSubscriptionDeletedResponse(
  message: ServerRealtimeWireMessage,
): message is SubscriptionDeletedV1 {
  return (
    message.type === "subscription.deleted" &&
    "subscription_id" in message.payload &&
    !("topic" in message.payload)
  );
}

function isServerMessage(
  message: RealtimeWireMessage,
): message is ServerRealtimeWireMessage {
  return !["subscription.create", "subscription.delete", "ping"].includes(
    message.type,
  );
}

type CorrelatedServerResponse =
  | SubscriptionCreatedV1
  | SubscriptionDeletedV1
  | CommandRejectedV1
  | PongV1;

function isCorrelatedResponse(
  message: ServerRealtimeWireMessage,
): message is CorrelatedServerResponse {
  if (message.correlation_id === null) {
    return false;
  }
  switch (message.type) {
    case "subscription.created":
      return "topic" in message.payload && "subscription_id" in message.payload;
    case "subscription.deleted":
      return (
        "subscription_id" in message.payload && !("topic" in message.payload)
      );
    case "command.rejected":
      return "code" in message.payload && "message" in message.payload;
    case "pong":
      return Object.keys(message.payload).length === 0;
    default:
      return false;
  }
}

function defaultWebSocketFactory(
  url: string,
  protocols: readonly string[],
): RealtimeWebSocketLike {
  if (typeof globalThis.WebSocket === "undefined") {
    throw new TypeError("WebSocket is not available in this environment");
  }
  return new globalThis.WebSocket(url, [...protocols]);
}

function validateProtocols(protocols: readonly string[]): readonly string[] {
  if (
    protocols.length === 0 ||
    protocols.length > 8 ||
    !protocols.includes(REALTIME_WEBSOCKET_PROTOCOL)
  ) {
    throw new TypeError(
      `WebSocket protocols must include ${REALTIME_WEBSOCKET_PROTOCOL}`,
    );
  }
  const unique = new Set<string>();
  for (const protocol of protocols) {
    if (
      protocol.length === 0 ||
      protocol.length > 128 ||
      !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(protocol) ||
      unique.has(protocol)
    ) {
      throw new TypeError("WebSocket protocols must be unique valid tokens");
    }
    unique.add(protocol);
  }
  return Object.freeze(Array.from(unique));
}

function boundedCodeSet(codes: readonly number[], name: string): ReadonlySet<number> {
  if (codes.length === 0 || codes.length > 16) {
    throw new RangeError(`${name} must contain between one and sixteen codes`);
  }
  const result = new Set<number>();
  for (const code of codes) {
    if (!Number.isSafeInteger(code) || code < 1000 || code > 4999) {
      throw new RangeError(`${name} contains an invalid WebSocket close code`);
    }
    result.add(code);
  }
  return result;
}

function safelyCloseSocket(
  socket: RealtimeWebSocketLike,
  code: number,
  reason: string,
): void {
  try {
    socket.close(code, reason);
  } catch {
    // Closing an already-closed browser socket is harmless.
  }
}
