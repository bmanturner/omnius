import type {
  RealtimeClock,
  RealtimeEventSourceLike,
  RealtimeQueryClient,
  RealtimeQueryKey,
  RealtimeSseEventListener,
  RealtimeTimers,
  RealtimeWebSocketLike,
} from "../realtime/index.js";

interface ScheduledTimer {
  readonly at: number;
  readonly order: number;
  readonly callback: () => void;
}

export interface ManualRealtimeTime extends RealtimeClock, RealtimeTimers {
  advanceBy(delayMs: number): void;
  pendingTimerCount(): number;
}

/** Deterministic clock/timer pair for reconnect, heartbeat, and timeout tests. */
export function createManualRealtimeTime(startAt = 0): ManualRealtimeTime {
  if (!Number.isFinite(startAt)) {
    throw new RangeError("startAt must be finite");
  }
  let current = startAt;
  let nextHandle = 1;
  let nextOrder = 1;
  const timers = new Map<number, ScheduledTimer>();

  return Object.freeze({
    now: () => current,
    setTimeout(callback: () => void, delayMs: number): number {
      if (!Number.isFinite(delayMs) || delayMs < 0) {
        throw new RangeError("delayMs must be a non-negative finite number");
      }
      const handle = nextHandle;
      nextHandle += 1;
      timers.set(handle, {
        at: current + delayMs,
        order: nextOrder,
        callback,
      });
      nextOrder += 1;
      return handle;
    },
    clearTimeout(handle: unknown): void {
      if (typeof handle === "number") {
        timers.delete(handle);
      }
    },
    advanceBy(delayMs: number): void {
      if (!Number.isFinite(delayMs) || delayMs < 0) {
        throw new RangeError("delayMs must be a non-negative finite number");
      }
      const target = current + delayMs;
      let callbacks = 0;
      for (;;) {
        let selectedHandle: number | undefined;
        let selected: ScheduledTimer | undefined;
        for (const [handle, timer] of timers) {
          if (
            timer.at <= target &&
            (selected === undefined ||
              timer.at < selected.at ||
              (timer.at === selected.at && timer.order < selected.order))
          ) {
            selectedHandle = handle;
            selected = timer;
          }
        }
        if (selectedHandle === undefined || selected === undefined) {
          break;
        }
        timers.delete(selectedHandle);
        current = selected.at;
        selected.callback();
        callbacks += 1;
        if (callbacks > 10_000) {
          throw new Error("Manual realtime time exceeded its callback safety limit");
        }
      }
      current = target;
    },
    pendingTimerCount: () => timers.size,
  });
}

export interface FakeWebSocketCloseCall {
  readonly code?: number;
  readonly reason?: string;
}

/** Browser-shaped WebSocket fake; the test controls every server-side transition explicitly. */
export class FakeRealtimeWebSocket implements RealtimeWebSocketLike {
  binaryType: BinaryType = "blob";
  readyState = 0;
  readonly protocol: string;
  onopen: ((event: Event) => unknown) | null = null;
  onmessage: ((event: MessageEvent<unknown>) => unknown) | null = null;
  onerror: ((event: Event) => unknown) | null = null;
  onclose: ((event: CloseEvent) => unknown) | null = null;
  readonly sent: string[] = [];
  readonly closeCalls: FakeWebSocketCloseCall[] = [];

  constructor(protocol = "omnius.realtime.v1") {
    this.protocol = protocol;
  }

  send(data: string): void {
    if (this.readyState !== 1) {
      throw new Error("Fake realtime WebSocket is not open");
    }
    this.sent.push(data);
  }

  close(code?: number, reason?: string): void {
    this.readyState = 3;
    this.closeCalls.push({
      ...(code === undefined ? {} : { code }),
      ...(reason === undefined ? {} : { reason }),
    });
  }

  open(): void {
    this.readyState = 1;
    this.onopen?.({ type: "open" } as Event);
  }

  receive(data: unknown): void {
    this.onmessage?.({ type: "message", data } as MessageEvent<unknown>);
  }

  fail(): void {
    this.onerror?.({ type: "error" } as Event);
  }

  closeFromServer(code = 1000, reason = ""): void {
    this.readyState = 3;
    this.onclose?.({
      type: "close",
      code,
      reason,
      wasClean: code === 1000,
    } as CloseEvent);
  }
}

export interface FakeRealtimeWebSocketFactory {
  readonly sockets: readonly FakeRealtimeWebSocket[];
  readonly requests: readonly {
    readonly url: string;
    readonly protocols: readonly string[];
  }[];
  create(url: string, protocols: readonly string[]): FakeRealtimeWebSocket;
}

export function createFakeRealtimeWebSocketFactory(
  negotiatedProtocol = "omnius.realtime.v1",
): FakeRealtimeWebSocketFactory {
  const sockets: FakeRealtimeWebSocket[] = [];
  const requests: Array<{ readonly url: string; readonly protocols: readonly string[] }> = [];
  return Object.freeze({
    sockets,
    requests,
    create(url: string, protocols: readonly string[]): FakeRealtimeWebSocket {
      requests.push({ url, protocols: Object.freeze([...protocols]) });
      const socket = new FakeRealtimeWebSocket(negotiatedProtocol);
      sockets.push(socket);
      return socket;
    },
  });
}

/** Browser-shaped EventSource fake with explicit named-event and failure controls. */
export class FakeRealtimeEventSource implements RealtimeEventSourceLike {
  readyState = 0;
  onopen: ((event: Event) => unknown) | null = null;
  onerror: ((event: Event) => unknown) | null = null;
  readonly url: string;
  readonly init: EventSourceInit;
  readonly comments: string[] = [];
  #listeners = new Map<string, Set<RealtimeSseEventListener>>();

  constructor(url: string, init: EventSourceInit) {
    this.url = url;
    this.init = init;
  }

  addEventListener(type: string, listener: RealtimeSseEventListener): void {
    let listeners = this.#listeners.get(type);
    if (listeners === undefined) {
      listeners = new Set();
      this.#listeners.set(type, listeners);
    }
    listeners.add(listener);
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
  }

  open(): void {
    this.readyState = 1;
    this.onopen?.({ type: "open" } as Event);
  }

  emit(eventName: string, data: string): void {
    const event = { type: eventName, data } as MessageEvent<string>;
    for (const listener of this.#listeners.get(eventName) ?? []) {
      listener(event);
    }
  }

  heartbeat(comment = "heartbeat"): void {
    this.comments.push(comment);
  }

  fail(status?: number): void {
    this.onerror?.({
      type: "error",
      ...(status === undefined ? {} : { status }),
    } as Event);
  }
}

export interface FakeRealtimeEventSourceFactory {
  readonly sources: readonly FakeRealtimeEventSource[];
  create(url: string, init: EventSourceInit): FakeRealtimeEventSource;
}

export function createFakeRealtimeEventSourceFactory(): FakeRealtimeEventSourceFactory {
  const sources: FakeRealtimeEventSource[] = [];
  return Object.freeze({
    sources,
    create(url: string, init: EventSourceInit): FakeRealtimeEventSource {
      const source = new FakeRealtimeEventSource(url, init);
      sources.push(source);
      return source;
    },
  });
}

export type RecordedRealtimeQueryOperation =
  | { readonly type: "invalidate"; readonly queryKey: RealtimeQueryKey }
  | { readonly type: "refetch"; readonly queryKey: RealtimeQueryKey }
  | { readonly type: "remove"; readonly queryKey: RealtimeQueryKey }
  | { readonly type: "set"; readonly queryKey: RealtimeQueryKey };

export interface RealtimeQueryClientFixture extends RealtimeQueryClient {
  prime<TData>(queryKey: RealtimeQueryKey, data: TData): void;
  get<TData>(queryKey: RealtimeQueryKey): TData | undefined;
  operations(): readonly RecordedRealtimeQueryOperation[];
}

/** Small query-cache fixture for asserting generated/scoped keys and safe writes. */
export function createRealtimeQueryClientFixture(): RealtimeQueryClientFixture {
  const data = new Map<string, unknown>();
  const recorded: RecordedRealtimeQueryOperation[] = [];
  return Object.freeze({
    invalidateQueries(queryKey: RealtimeQueryKey): void {
      recorded.push({ type: "invalidate", queryKey });
    },
    refetchQueries(queryKey: RealtimeQueryKey): void {
      recorded.push({ type: "refetch", queryKey });
    },
    removeQueries(queryKey: RealtimeQueryKey): void {
      recorded.push({ type: "remove", queryKey });
      data.delete(stableQueryKey(queryKey));
    },
    setQueryData<TData>(
      queryKey: RealtimeQueryKey,
      updater: (current: TData | undefined) => TData | undefined,
    ): void {
      const id = stableQueryKey(queryKey);
      const next = updater(data.get(id) as TData | undefined);
      if (next === undefined) {
        data.delete(id);
      } else {
        data.set(id, next);
      }
      recorded.push({ type: "set", queryKey });
    },
    prime<TData>(queryKey: RealtimeQueryKey, value: TData): void {
      data.set(stableQueryKey(queryKey), value);
    },
    get<TData>(queryKey: RealtimeQueryKey): TData | undefined {
      return data.get(stableQueryKey(queryKey)) as TData | undefined;
    },
    operations(): readonly RecordedRealtimeQueryOperation[] {
      return Object.freeze(recorded.slice());
    },
  });
}

function stableQueryKey(value: unknown): string {
  const active = new Set<object>();
  const normalize = (candidate: unknown): unknown => {
    if (Array.isArray(candidate)) {
      if (active.has(candidate)) {
        throw new TypeError("Realtime query fixture keys must not be cyclic");
      }
      active.add(candidate);
      const normalized = candidate.map(normalize);
      active.delete(candidate);
      return normalized;
    }
    if (typeof candidate !== "object" || candidate === null) {
      return candidate;
    }
    if (active.has(candidate)) {
      throw new TypeError("Realtime query fixture keys must not be cyclic");
    }
    active.add(candidate);
    const normalized: Record<string, unknown> = {};
    for (const key of Object.keys(candidate).sort()) {
      normalized[key] = normalize((candidate as Record<string, unknown>)[key]);
    }
    active.delete(candidate);
    return normalized;
  };
  const serialized = JSON.stringify(normalize(value));
  if (serialized === undefined) {
    throw new TypeError("Realtime query fixture key is not serializable");
  }
  return serialized;
}
