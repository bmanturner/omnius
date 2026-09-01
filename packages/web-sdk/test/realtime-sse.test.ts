import { describe, expect, it, vi } from "vitest";

import type { DomainEventV1 } from "../src/internal/generated/realtime.js";
import { createSseTransport } from "../src/realtime/index.js";
import type {
  RealtimeEventSourceLike,
  RealtimeSseEventListener,
  RealtimeTransportConnectOptions,
} from "../src/realtime/index.js";

const EVENT_ID = "01890f47-7e7a-7c8a-9abc-1234567890ab";
const SUBSCRIPTION_ID = "01890f47-7e7a-7c8a-9abc-1234567890ac";
const TOPIC = "organization.updated.v1";

class SseDataEvent extends Event {
  constructor(type: string, readonly data: string) {
    super(type);
  }
}

class EventSourceFake implements RealtimeEventSourceLike {
  readyState = 0;
  onopen: ((event: Event) => unknown) | null = null;
  onerror: ((event: Event) => unknown) | null = null;
  closeCount = 0;
  readonly #listeners = new Map<string, Set<RealtimeSseEventListener>>();

  addEventListener(type: string, listener: RealtimeSseEventListener): void {
    const listeners =
      this.#listeners.get(type) ?? new Set<RealtimeSseEventListener>();
    listeners.add(listener);
    this.#listeners.set(type, listeners);
  }

  removeEventListener(type: string, listener: RealtimeSseEventListener): void {
    const listeners = this.#listeners.get(type);
    listeners?.delete(listener);
    if (listeners?.size === 0) {
      this.#listeners.delete(type);
    }
  }

  close(): void {
    this.readyState = 2;
    this.closeCount += 1;
  }

  open(): void {
    this.readyState = 1;
    this.onopen?.(new Event("open"));
  }

  emit(type: string, data: string): void {
    for (const listener of this.#listeners.get(type) ?? []) {
      listener(new SseDataEvent(type, data));
    }
  }

  listenerCount(): number {
    let count = 0;
    for (const listeners of this.#listeners.values()) {
      count += listeners.size;
    }
    return count;
  }
}

function callbacks(signal: AbortSignal = new AbortController().signal): RealtimeTransportConnectOptions {
  return {
    cursor: "cursor-2",
    signal,
    subscriptions: [
      { id: SUBSCRIPTION_ID, topic: TOPIC, cursor: "cursor-2" },
    ],
    onOpen: vi.fn(),
    onMessage: vi.fn(),
    onClose: vi.fn(),
    onDegraded: vi.fn(),
    onDiagnostic: vi.fn(),
  };
}

function domainEvent(): DomainEventV1 {
  return {
    v: 1,
    id: EVENT_ID,
    type: TOPIC,
    correlation_id: null,
    payload: {
      subscription_id: SUBSCRIPTION_ID,
      topic: TOPIC,
      cursor: "cursor-3",
      data: { organization_id: "organization-1" },
    },
  };
}

describe("SSE realtime transport", () => {
  it("resumes with transport-managed query parameters, receives a named event, and honors drain hints", () => {
    const source = new EventSourceFake();
    const factory = vi.fn(() => source);
    const connection = callbacks();
    const transport = createSseTransport({
      baseUrl: "https://app.example.test/dashboard",
      eventSourceFactory: factory,
      eventNames: [TOPIC],
    });

    transport.connect(connection);
    expect(factory).toHaveBeenCalledWith(
      `https://app.example.test/dashboard/realtime/events?subscription_id=${SUBSCRIPTION_ID}&topic=${TOPIC}&cursor=cursor-2`,
      { withCredentials: false },
    );
    source.open();
    source.emit(TOPIC, JSON.stringify(domainEvent()));
    expect(connection.onOpen).toHaveBeenCalledOnce();
    expect(connection.onMessage).toHaveBeenCalledWith(domainEvent());

    source.emit("reconnect", "server-draining");
    expect(connection.onClose).toHaveBeenCalledWith({
      reason: "server-draining",
      reconnect: true,
    });
    expect(source.closeCount).toBe(1);
    expect(source.listenerCount()).toBe(0);
    source.emit(TOPIC, JSON.stringify(domainEvent()));
    expect(connection.onMessage).toHaveBeenCalledOnce();
  });

  it("never sends Last-Event-ID, ignores SSE id fields, and cancels the fetch stream", async () => {
    const externalAbort = new AbortController();
    const connection = callbacks(externalAbort.signal);
    const encodedEvent = new TextEncoder().encode(
      `id: ignored-transport-id\nevent: ${TOPIC}\ndata: ${JSON.stringify(domainEvent())}\n\n`,
    );
    let requestSignal: AbortSignal | undefined;
    const fetchImplementation: typeof fetch = vi.fn(async (_input, init) => {
      requestSignal = init?.signal ?? undefined;
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encodedEvent);
          init?.signal?.addEventListener(
            "abort",
            () => controller.close(),
            { once: true },
          );
        },
      });
      return new Response(stream, {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      });
    });
    const getHeaders = vi.fn(() => ({ authorization: "Bearer test-only" }));
    const transport = createSseTransport({
      baseUrl: "https://app.example.test",
      headerAuthentication: { getHeaders },
      fetch: fetchImplementation,
    });

    transport.connect(connection);
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    expect(getHeaders).toHaveBeenCalledWith({
      url: new URL(
        `https://app.example.test/realtime/events?subscription_id=${SUBSCRIPTION_ID}&topic=${TOPIC}&cursor=cursor-2`,
      ),
      signal: expect.any(AbortSignal),
    });
    expect(fetchImplementation).toHaveBeenCalledOnce();
    const fetchInit = vi.mocked(fetchImplementation).mock.calls[0]?.[1];
    const headers = new Headers(fetchInit?.headers);
    expect(headers.get("last-event-id")).toBeNull();
    expect(headers.get("accept")).toBe("text/event-stream");
    expect(connection.onMessage).toHaveBeenCalledWith(domainEvent());

    externalAbort.abort();
    await Promise.resolve();
    expect(requestSignal?.aborted).toBe(true);
    expect(connection.onClose).not.toHaveBeenCalled();
  });

  it("rejects an application-supplied Last-Event-ID instead of creating an ambiguous resume", async () => {
    const connection = callbacks();
    const fetchImplementation: typeof fetch = vi.fn(
      async () => new Response(null, { status: 204 }),
    );
    const transport = createSseTransport({
      baseUrl: "https://app.example.test",
      headerAuthentication: {
        getHeaders: () => ({ "Last-Event-ID": "ambiguous-id" }),
      },
      fetch: fetchImplementation,
    });

    transport.connect(connection);
    await Promise.resolve();
    await Promise.resolve();
    expect(fetchImplementation).not.toHaveBeenCalled();
    expect(connection.onDiagnostic).toHaveBeenCalledWith({ code: "protocol-error" });
    expect(connection.onClose).toHaveBeenCalledWith({
      reason: "protocol-error",
      reconnect: false,
    });
    transport.disconnect();
  });
});
