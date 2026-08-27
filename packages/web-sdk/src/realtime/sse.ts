import {
  isSameOrigin,
  positiveInteger,
  resolveHttpUrl,
  utf8ByteLength,
  validateCursor,
  validateTopic,
  validateUuidV7,
} from "./internals.js";
import type {
  RealtimeDisconnectReason,
  RealtimeTransportClose,
  RealtimeTransportConnectOptions,
  RealtimeTransportPort,
  RealtimeTransportSubscription,
} from "./types.js";

const DEFAULT_SSE_PATH = "/events";
const DEFAULT_MAX_MESSAGE_SIZE_BYTES = 256 * 1024;
const DEFAULT_MAX_EVENT_NAMES = 256;
const DEFAULT_MAX_SUBSCRIPTIONS = 256;

export type RealtimeSseEventListener = (event: Event) => void;

export interface RealtimeEventSourceLike {
  readonly readyState: number;
  onopen: ((event: Event) => unknown) | null;
  onerror: ((event: Event) => unknown) | null;
  addEventListener(type: string, listener: RealtimeSseEventListener): void;
  removeEventListener(type: string, listener: RealtimeSseEventListener): void;
  close(): void;
}

/** Explicit, application-approved custom-header authentication for fetch streaming. */
export interface RealtimeSseHeaderAuthenticationStrategy {
  getHeaders(input: {
    readonly url: URL;
    readonly signal: AbortSignal;
  }): HeadersInit | Promise<HeadersInit>;
}

export interface RealtimeSseTransportOptions {
  readonly url?: string | URL;
  readonly baseUrl?: string | URL;
  readonly eventSourceFactory?: (
    url: string,
    init: EventSourceInit,
  ) => RealtimeEventSourceLike;
  readonly headerAuthentication?: RealtimeSseHeaderAuthenticationStrategy;
  readonly fetch?: typeof globalThis.fetch;
  /** Domain wire event names to register on native EventSource. */
  readonly eventNames?: readonly string[];
  readonly maxMessageSizeBytes?: number;
  readonly maxEventNames?: number;
  readonly maxSubscriptions?: number;
}

export function createSseTransport(
  options: RealtimeSseTransportOptions = {},
): RealtimeTransportPort {
  return new SseRealtimeTransport(options);
}

interface SseSourceConnection {
  readonly subscription: RealtimeTransportSubscription;
  readonly abort: AbortController;
  eventSource?: RealtimeEventSourceLike;
  readonly listeners: Map<string, RealtimeSseEventListener>;
}

class SseRealtimeTransport implements RealtimeTransportPort {
  readonly kind = "sse" as const;
  readonly #configuredUrl;
  readonly #baseUrl;
  readonly #eventSourceFactory;
  readonly #headerAuthentication;
  readonly #fetch;
  readonly #configuredEventNames;
  readonly #maxMessageSizeBytes;
  readonly #maxSubscriptions;
  readonly #sources = new Map<string, SseSourceConnection>();

  #callbacks: RealtimeTransportConnectOptions | undefined;
  #abortCleanup: (() => void) | undefined;
  #ended = true;
  #opened = false;
  #endpoint: URL | undefined;

  constructor(options: RealtimeSseTransportOptions) {
    this.#configuredUrl = options.url;
    this.#baseUrl = options.baseUrl;
    this.#eventSourceFactory =
      options.eventSourceFactory ?? defaultEventSourceFactory;
    this.#headerAuthentication = options.headerAuthentication;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#configuredEventNames = Object.freeze([
      ...new Set(options.eventNames ?? []),
    ]);
    this.#maxMessageSizeBytes = positiveInteger(
      options.maxMessageSizeBytes ?? DEFAULT_MAX_MESSAGE_SIZE_BYTES,
      "maxMessageSizeBytes",
    );
    const maxEventNames = positiveInteger(
      options.maxEventNames ?? DEFAULT_MAX_EVENT_NAMES,
      "maxEventNames",
    );
    this.#maxSubscriptions = positiveInteger(
      options.maxSubscriptions ?? DEFAULT_MAX_SUBSCRIPTIONS,
      "maxSubscriptions",
    );
    if (this.#configuredEventNames.length > maxEventNames) {
      throw new RangeError("eventNames exceeds maxEventNames");
    }
    for (const eventName of this.#configuredEventNames) {
      validateTopic(eventName);
    }
  }

  connect(callbacks: RealtimeTransportConnectOptions): void {
    this.disconnect("client-disconnect");
    const { base, url } = resolveHttpUrl(
      this.#configuredUrl,
      DEFAULT_SSE_PATH,
      this.#baseUrl,
    );
    if (url.username.length !== 0 || url.password.length !== 0) {
      throw new TypeError("SSE URLs must not contain URL credentials");
    }
    if (Array.from(url.searchParams.keys()).length !== 0) {
      throw new TypeError("SSE URL query parameters are transport-managed");
    }
    if (this.#headerAuthentication === undefined && !isSameOrigin(base, url)) {
      throw new TypeError("Ambient-cookie EventSource must be same-origin");
    }
    if (callbacks.subscriptions.length > this.#maxSubscriptions) {
      throw new RangeError("The SSE subscription limit has been reached");
    }

    this.#endpoint = url;
    this.#callbacks = callbacks;
    this.#ended = false;
    this.#opened = false;
    const fallbackCursor =
      callbacks.subscriptions.length === 1 ? callbacks.cursor : undefined;
    const abortListener = () => this.disconnect("client-disconnect");
    callbacks.signal.addEventListener("abort", abortListener, { once: true });
    this.#abortCleanup = () => {
      callbacks.signal.removeEventListener("abort", abortListener);
    };

    try {
      for (const subscription of callbacks.subscriptions) {
        this.#openSource(subscription, fallbackCursor);
      }
    } catch (error) {
      this.disconnect("protocol-error");
      throw error;
    }
    if (callbacks.subscriptions.length === 0) {
      this.#notifyOpen();
    }
  }

  disconnect(_reason: RealtimeDisconnectReason = "client-disconnect"): void {
    this.#ended = true;
    this.#abortCleanup?.();
    this.#abortCleanup = undefined;
    for (const source of this.#sources.values()) {
      closeSource(source);
    }
    this.#sources.clear();
    this.#callbacks = undefined;
    this.#endpoint = undefined;
    this.#opened = false;
  }

  async subscribe(subscription: RealtimeTransportSubscription): Promise<void> {
    if (this.#ended || this.#callbacks === undefined) {
      throw new Error("The SSE transport is not connected");
    }
    if (this.#sources.has(subscription.id)) {
      return;
    }
    if (this.#sources.size >= this.#maxSubscriptions) {
      throw new RangeError("The SSE subscription limit has been reached");
    }
    this.#openSource(subscription);
  }

  async unsubscribe(subscriptionId: string): Promise<void> {
    const source = this.#sources.get(subscriptionId);
    if (source !== undefined) {
      this.#sources.delete(subscriptionId);
      closeSource(source);
    }
  }

  #openSource(
    subscription: RealtimeTransportSubscription,
    fallbackCursor?: string,
  ): void {
    validateUuidV7(subscription.id, "subscription id");
    validateTopic(subscription.topic);
    const endpoint = this.#endpoint;
    if (endpoint === undefined) {
      throw new Error("The SSE transport is not connected");
    }
    const cursor = subscription.cursor ?? fallbackCursor;
    if (cursor !== undefined) {
      validateCursor(cursor);
    }
    const url = new URL(endpoint.toString());
    url.searchParams.set("subscription_id", subscription.id);
    url.searchParams.set("topic", subscription.topic);
    if (cursor !== undefined) {
      url.searchParams.set("cursor", cursor);
    }
    const source: SseSourceConnection = {
      subscription,
      abort: new AbortController(),
      listeners: new Map(),
    };
    this.#sources.set(subscription.id, source);
    if (this.#headerAuthentication === undefined) {
      this.#openNativeSource(source, url);
    } else {
      void this.#openFetchSource(source, url);
    }
  }

  #openNativeSource(source: SseSourceConnection, url: URL): void {
    const callbacks = this.#callbacks;
    if (callbacks === undefined || this.#ended) {
      return;
    }
    const eventSource = this.#eventSourceFactory(url.toString(), {
      withCredentials: false,
    });
    source.eventSource = eventSource;
    eventSource.onopen = () => {
      if (this.#isActive(source)) {
        this.#notifyOpen();
      }
    };
    eventSource.onerror = (event) => {
      if (!this.#isActive(source)) {
        return;
      }
      const status = readHttpStatus(event);
      this.#finish(
        status === 401 || status === 403
          ? {
              reason: "unauthorized",
              reconnect: false,
              unauthorized: true,
            }
          : { reason: "network-error", reconnect: true },
      );
    };
    this.#attachNativeListener(source, "subscription.revoked");
    this.#attachNativeListener(source, "reconnect");
    for (const eventName of this.#configuredEventNames) {
      this.#attachNativeListener(source, eventName);
    }
  }

  #attachNativeListener(
    source: SseSourceConnection,
    eventName: string,
  ): void {
    const eventSource = source.eventSource;
    if (eventSource === undefined || source.listeners.has(eventName)) {
      return;
    }
    const listener: RealtimeSseEventListener = (event) => {
      if (!this.#isActive(source)) {
        return;
      }
      const data = readEventData(event);
      if (data !== undefined) {
        this.#handleSseEvent(eventName, data);
      }
    };
    source.listeners.set(eventName, listener);
    eventSource.addEventListener(eventName, listener);
  }

  async #openFetchSource(
    source: SseSourceConnection,
    url: URL,
  ): Promise<void> {
    const callbacks = this.#callbacks;
    if (callbacks === undefined || this.#ended) {
      return;
    }
    try {
      if (typeof this.#fetch !== "function") {
        throw new TypeError("fetch is not available in this environment");
      }
      const providedHeaders = await this.#headerAuthentication?.getHeaders({
        url: new URL(url.toString()),
        signal: source.abort.signal,
      });
      if (!this.#isActive(source)) {
        return;
      }
      const headers = new Headers(providedHeaders);
      if (headers.has("Last-Event-ID")) {
        throw new TypeError("Last-Event-ID is forbidden; use the cursor query");
      }
      headers.set("Accept", "text/event-stream");
      const response = await this.#fetch(url, {
        method: "GET",
        headers,
        signal: source.abort.signal,
        credentials: "omit",
        redirect: "error",
      });
      if (!this.#isActive(source)) {
        return;
      }
      if (response.status === 401 || response.status === 403) {
        this.#finish({
          reason: "unauthorized",
          reconnect: false,
          unauthorized: true,
        });
        return;
      }
      if (!response.ok || response.body === null) {
        callbacks.onDiagnostic({ code: "transport-error" });
        this.#finish({ reason: "network-error", reconnect: true });
        return;
      }
      this.#notifyOpen();
      const parser = new SseParser(
        this.#maxMessageSizeBytes,
        (eventName, data) => this.#handleSseEvent(eventName, data),
      );
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      while (this.#isActive(source)) {
        const result = await reader.read();
        if (result.done) {
          const finalText = decoder.decode();
          if (finalText.length !== 0) {
            parser.push(finalText);
          }
          break;
        }
        parser.push(decoder.decode(result.value, { stream: true }));
      }
      if (this.#isActive(source)) {
        this.#finish({ reason: "network-error", reconnect: true });
      }
    } catch (error) {
      if (!this.#isActive(source)) {
        return;
      }
      if (error instanceof SseMessageTooLargeError) {
        callbacks.onDiagnostic({ code: "message-too-large" });
        this.#finish({ reason: "protocol-error", reconnect: false });
      } else if (error instanceof SseProtocolError || error instanceof TypeError) {
        callbacks.onDiagnostic({ code: "protocol-error" });
        this.#finish({ reason: "protocol-error", reconnect: false });
      } else {
        callbacks.onDiagnostic({ code: "transport-error" });
        this.#finish({ reason: "network-error", reconnect: true });
      }
    }
  }

  #handleSseEvent(eventName: string, data: string): void {
    const callbacks = this.#callbacks;
    if (callbacks === undefined || this.#ended) {
      return;
    }
    if (utf8ByteLength(data) > this.#maxMessageSizeBytes) {
      callbacks.onDiagnostic({ code: "message-too-large" });
      this.#finish({ reason: "protocol-error", reconnect: false });
      return;
    }
    if (eventName === "reconnect") {
      if (data === "server-draining" || data === "slow-consumer") {
        this.#finish({ reason: data, reconnect: true });
      } else {
        callbacks.onDiagnostic({ code: "protocol-error" });
      }
      return;
    }
    try {
      callbacks.onMessage(JSON.parse(data) as unknown);
    } catch {
      callbacks.onMessage(data);
    }
  }

  #notifyOpen(): void {
    if (!this.#opened && !this.#ended) {
      this.#opened = true;
      this.#callbacks?.onOpen();
    }
  }

  #finish(close: RealtimeTransportClose): void {
    if (this.#ended) {
      return;
    }
    const callbacks = this.#callbacks;
    this.#ended = true;
    this.#abortCleanup?.();
    this.#abortCleanup = undefined;
    for (const source of this.#sources.values()) {
      closeSource(source);
    }
    this.#sources.clear();
    this.#callbacks = undefined;
    this.#endpoint = undefined;
    callbacks?.onClose(close);
  }

  #isActive(source: SseSourceConnection): boolean {
    return (
      !this.#ended &&
      this.#sources.get(source.subscription.id) === source &&
      !source.abort.signal.aborted
    );
  }
}

class SseMessageTooLargeError extends Error {}
class SseProtocolError extends Error {}

class SseParser {
  readonly #maxMessageSizeBytes;
  readonly #onEvent;
  #buffer = "";
  #eventName = "message";
  #dataLines: string[] = [];
  #eventBytes = 0;

  constructor(
    maxMessageSizeBytes: number,
    onEvent: (eventName: string, data: string) => void,
  ) {
    this.#maxMessageSizeBytes = maxMessageSizeBytes;
    this.#onEvent = onEvent;
  }

  push(chunk: string): void {
    this.#buffer += chunk;
    if (utf8ByteLength(this.#buffer) > this.#maxMessageSizeBytes) {
      throw new SseMessageTooLargeError();
    }
    let newline = this.#buffer.indexOf("\n");
    while (newline >= 0) {
      let line = this.#buffer.slice(0, newline);
      this.#buffer = this.#buffer.slice(newline + 1);
      if (line.endsWith("\r")) {
        line = line.slice(0, -1);
      }
      this.#consumeLine(line);
      newline = this.#buffer.indexOf("\n");
    }
  }

  #consumeLine(line: string): void {
    if (line.length === 0) {
      if (this.#dataLines.length !== 0) {
        if (this.#eventName.length === 0) {
          throw new SseProtocolError();
        }
        this.#onEvent(this.#eventName, this.#dataLines.join("\n"));
      }
      this.#eventName = "message";
      this.#dataLines = [];
      this.#eventBytes = 0;
      return;
    }
    if (line.startsWith(":")) {
      return;
    }
    const separator = line.indexOf(":");
    const field = separator < 0 ? line : line.slice(0, separator);
    let value = separator < 0 ? "" : line.slice(separator + 1);
    if (value.startsWith(" ")) {
      value = value.slice(1);
    }
    if (field === "event") {
      this.#eventName =
        value.length <= 128 &&
        /^[A-Za-z0-9._:/-]+(?![\s\S])/u.test(value)
          ? value
          : "";
      return;
    }
    if (field !== "data") {
      // `id` and `retry` are deliberately ignored. Resume is cursor-query only.
      return;
    }
    this.#eventBytes += utf8ByteLength(value) + 1;
    if (this.#eventBytes > this.#maxMessageSizeBytes) {
      throw new SseMessageTooLargeError();
    }
    this.#dataLines.push(value);
  }
}

function closeSource(source: SseSourceConnection): void {
  source.abort.abort();
  const eventSource = source.eventSource;
  if (eventSource === undefined) {
    return;
  }
  eventSource.onopen = null;
  eventSource.onerror = null;
  for (const [eventName, listener] of source.listeners) {
    eventSource.removeEventListener(eventName, listener);
  }
  source.listeners.clear();
  eventSource.close();
}

function defaultEventSourceFactory(
  url: string,
  init: EventSourceInit,
): RealtimeEventSourceLike {
  if (typeof globalThis.EventSource === "undefined") {
    throw new TypeError("EventSource is not available in this environment");
  }
  return new globalThis.EventSource(url, init);
}

function readEventData(event: Event): string | undefined {
  if ("data" in event && typeof event.data === "string") {
    return event.data;
  }
  return undefined;
}

function readHttpStatus(event: Event): number | undefined {
  if ("status" in event && typeof event.status === "number") {
    return event.status;
  }
  return undefined;
}
