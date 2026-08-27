import { describe, expect, it, vi } from "vitest";

import type {
  ClientRealtimeWireMessage,
  PingV1,
} from "../src/internal/generated/realtime.js";
import {
  REALTIME_WEBSOCKET_PROTOCOL,
  RealtimeCommandCapacityError,
  RealtimeCommandRejectedError,
  createWebSocketTransport,
} from "../src/realtime/index.js";
import type {
  RealtimeTransportConnectOptions,
  RealtimeWebSocketLike,
} from "../src/realtime/index.js";

const IDS = [
  "01890f47-7e7a-7c8a-9abc-1234567890ab",
  "01890f47-7e7a-7c8a-9abc-1234567890ac",
  "01890f47-7e7a-7c8a-9abc-1234567890ad",
  "01890f47-7e7a-7c8a-9abc-1234567890ae",
] as const;

class CloseEventFake extends Event implements CloseEvent {
  readonly reason = "";
  readonly wasClean = false;

  constructor(readonly code: number) {
    super("close");
  }
}

class WebSocketFake implements RealtimeWebSocketLike {
  binaryType: BinaryType = "blob";
  readyState = 0;
  readonly protocol = REALTIME_WEBSOCKET_PROTOCOL;
  onopen: ((event: Event) => unknown) | null = null;
  onmessage: ((event: MessageEvent<unknown>) => unknown) | null = null;
  onerror: ((event: Event) => unknown) | null = null;
  onclose: ((event: CloseEvent) => unknown) | null = null;
  readonly sent: string[] = [];
  readonly closes: Array<{ readonly code?: number; readonly reason?: string }> = [];

  send(data: string): void {
    this.sent.push(data);
  }

  close(code?: number, reason?: string): void {
    this.readyState = 3;
    this.closes.push({
      ...(code === undefined ? {} : { code }),
      ...(reason === undefined ? {} : { reason }),
    });
  }

  open(): void {
    this.readyState = 1;
    this.onopen?.(new Event("open"));
  }

  message(data: unknown): void {
    this.onmessage?.(new MessageEvent("message", { data }));
  }

  serverClose(code: number): void {
    this.readyState = 3;
    this.onclose?.(new CloseEventFake(code));
  }
}

function idFactory(): () => string {
  let next = 0;
  return () => {
    const id = IDS[next];
    next += 1;
    if (id === undefined) {
      throw new Error("The WebSocket test exhausted its identifiers");
    }
    return id;
  };
}

function callbacks(): RealtimeTransportConnectOptions {
  return {
    signal: new AbortController().signal,
    subscriptions: [],
    onOpen: vi.fn(),
    onMessage: vi.fn(),
    onClose: vi.fn(),
    onDegraded: vi.fn(),
    onDiagnostic: vi.fn(),
  };
}

function ping(id: string): PingV1 {
  return {
    v: 1,
    id,
    type: "ping",
    correlation_id: null,
    payload: {},
  };
}

describe("WebSocket realtime transport", () => {
  it("correlates a command denial without exposing its server message", async () => {
    const socket = new WebSocketFake();
    const connection = callbacks();
    const factory = vi.fn(() => socket);
    const generateId = vi.fn(idFactory());
    const transport = createWebSocketTransport({
      idFactory: generateId,
      baseUrl: "https://app.example.test/dashboard",
      webSocketFactory: factory,
      heartbeatIntervalMs: 20_000,
      idleTimeoutMs: 60_000,
    });

    transport.connect(connection);
    expect(factory).toHaveBeenCalledWith(
      "wss://app.example.test/realtime/ws",
      [REALTIME_WEBSOCKET_PROTOCOL],
    );
    expect(socket.binaryType).toBe("arraybuffer");
    socket.open();
    const pending = transport.sendCommand?.(ping(IDS[1]));
    if (pending === undefined) {
      throw new Error("The WebSocket transport must support commands");
    }
    const serialized = JSON.parse(socket.sent[0] ?? "null") as unknown;
    expect(serialized).toEqual({
      v: 1,
      id: IDS[1],
      type: "ping",
      correlation_id: null,
      payload: {},
    });
    expect(generateId).not.toHaveBeenCalled();

    let settled = false;
    void pending.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    socket.message(
      JSON.stringify({
        v: 1,
        id: IDS[2],
        type: "command.rejected",
        correlation_id: IDS[0],
        payload: { code: "unavailable", message: "Unrelated command" },
      }),
    );
    await Promise.resolve();
    await Promise.resolve();
    expect(settled).toBe(false);

    socket.message(
      JSON.stringify({
        v: 1,
        id: IDS[3],
        type: "command.rejected",
        correlation_id: IDS[1],
        payload: { code: "unauthorized", message: "Command not authorized" },
      }),
    );
    await expect(pending).rejects.toMatchObject({
      name: "RealtimeCommandRejectedError",
      code: "unauthorized",
    });
    await expect(pending).rejects.toBeInstanceOf(RealtimeCommandRejectedError);
    await expect(pending).rejects.not.toMatchObject({
      message: "Command not authorized",
    });
    expect(connection.onMessage).toHaveBeenLastCalledWith({
      v: 1,
      id: IDS[3],
      type: "command.rejected",
      correlation_id: IDS[1],
      payload: { code: "unauthorized", message: "Command not authorized" },
    });
    transport.disconnect();
  });

  it("rejects an invalid outbound command before writing to the socket", async () => {
    const socket = new WebSocketFake();
    const transport = createWebSocketTransport({
      idFactory: idFactory(),
      baseUrl: "https://app.example.test",
      webSocketFactory: () => socket,
      heartbeatIntervalMs: 20_000,
      idleTimeoutMs: 60_000,
    });
    transport.connect(callbacks());
    socket.open();
    const invalidCommand = {
      ...ping(IDS[1]),
      payload: { unexpected: true },
    } as unknown as ClientRealtimeWireMessage;
    const pending = transport.sendCommand?.(invalidCommand);
    if (pending === undefined) {
      throw new Error("The WebSocket transport must support commands");
    }

    await expect(pending).rejects.toThrow(/violates the wire contract/iu);
    expect(socket.sent).toEqual([]);
    transport.disconnect();
  });

  it("maps unauthorized and server-drain close codes without retrying authorization failures", () => {
    const firstSocket = new WebSocketFake();
    const secondSocket = new WebSocketFake();
    const sockets = [firstSocket, secondSocket];
    let nextSocket = 0;
    const transport = createWebSocketTransport({
      idFactory: idFactory(),
      baseUrl: "https://app.example.test",
      webSocketFactory: () => {
        const socket = sockets[nextSocket];
        nextSocket += 1;
        if (socket === undefined) {
          throw new Error("The WebSocket test exhausted its sockets");
        }
        return socket;
      },
      heartbeatIntervalMs: 20_000,
      idleTimeoutMs: 60_000,
    });
    const unauthorized = callbacks();
    transport.connect(unauthorized);
    firstSocket.open();
    firstSocket.serverClose(4401);
    expect(unauthorized.onClose).toHaveBeenCalledWith({
      reason: "unauthorized",
      reconnect: false,
      unauthorized: true,
      closeCode: 4401,
    });

    const draining = callbacks();
    transport.connect(draining);
    secondSocket.open();
    secondSocket.serverClose(1012);
    expect(draining.onClose).toHaveBeenCalledWith({
      reason: "server-draining",
      reconnect: true,
      closeCode: 1012,
    });
    transport.disconnect();
  });

  it("bounds pending commands and rejects all pending work on disconnect", async () => {
    const socket = new WebSocketFake();
    const transport = createWebSocketTransport({
      idFactory: idFactory(),
      baseUrl: "https://app.example.test",
      webSocketFactory: () => socket,
      maxPendingCommands: 1,
      heartbeatIntervalMs: 20_000,
      idleTimeoutMs: 60_000,
    });
    transport.connect(callbacks());
    socket.open();
    const first = transport.sendCommand?.(ping(IDS[1]));
    const second = transport.sendCommand?.(ping(IDS[2]));
    if (first === undefined || second === undefined) {
      throw new Error("The WebSocket transport must support commands");
    }

    await expect(second).rejects.toBeInstanceOf(RealtimeCommandCapacityError);
    expect(socket.sent).toHaveLength(1);
    const disconnected = expect(first).rejects.toMatchObject({ name: "AbortError" });
    transport.disconnect();
    await disconnected;
    expect(socket.closes.at(-1)).toEqual({ code: 1000, reason: "client-disconnect" });
  });
});
