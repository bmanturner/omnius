import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  DomainEventV1,
  SubscriptionRevokedV1,
} from "../src/internal/generated/realtime.js";
import { createRealtimeManager } from "../src/realtime/index.js";
import type {
  RealtimeDisconnectReason,
  RealtimeManager,
  RealtimeTransportClose,
  RealtimeTransportConnectOptions,
  RealtimeTransportPort,
  RealtimeTransportSubscription,
} from "../src/realtime/index.js";

const EVENT_IDS = [
  "01890f47-7e7a-7c8a-9abc-1234567890ab",
  "01890f47-7e7a-7c8a-9abc-1234567890ac",
  "01890f47-7e7a-7c8a-9abc-1234567890ad",
  "01890f47-7e7a-7c8a-9abc-1234567890ae",
] as const;
const SUBSCRIPTION_IDS = [
  "01890f47-7e7a-7c8a-9abc-1234567890b1",
  "01890f47-7e7a-7c8a-9abc-1234567890b2",
  "01890f47-7e7a-7c8a-9abc-1234567890b3",
] as const;

class ControlledTransport implements RealtimeTransportPort {
  readonly kind = "websocket" as const;
  readonly connections: RealtimeTransportConnectOptions[] = [];
  readonly disconnects: (RealtimeDisconnectReason | undefined)[] = [];
  readonly subscriptions: RealtimeTransportSubscription[] = [];

  connect(options: RealtimeTransportConnectOptions): void {
    this.connections.push(options);
  }

  disconnect(reason?: RealtimeDisconnectReason): void {
    this.disconnects.push(reason);
  }

  async subscribe(subscription: RealtimeTransportSubscription): Promise<void> {
    this.subscriptions.push(subscription);
  }

  open(): void {
    this.current().onOpen();
  }

  message(message: unknown): void {
    this.current().onMessage(message);
  }

  close(close: RealtimeTransportClose): void {
    this.current().onClose(close);
  }

  private current(): RealtimeTransportConnectOptions {
    const current = this.connections.at(-1);
    if (current === undefined) {
      throw new Error("The controlled transport is not connected");
    }
    return current;
  }
}

function idFactory(): () => string {
  let next = 0;
  return () => {
    const id = SUBSCRIPTION_IDS[next];
    next += 1;
    if (id === undefined) {
      throw new Error("The test exhausted its subscription identifiers");
    }
    return id;
  };
}

function domainEvent(
  subscriptionId: string,
  id: string = EVENT_IDS[0],
  cursor: string | null = "cursor-2",
): DomainEventV1 {
  return {
    v: 1,
    id,
    type: "organization.updated.v1",
    correlation_id: null,
    payload: {
      subscription_id: subscriptionId,
      topic: "organizations/organization-1",
      cursor,
      data: { organization_id: "organization-1" },
    },
  };
}

function latestReconnectDelay(manager: RealtimeManager): number {
  const diagnostic = manager.diagnostics.findLast(
    (candidate) => candidate.code === "reconnect-scheduled",
  );
  if (diagnostic?.delayMs === undefined) {
    throw new Error("Expected a reconnect-scheduled diagnostic with a delay");
  }
  return diagnostic.delayMs;
}

afterEach(() => {
  vi.useRealTimers();
});

describe("realtime manager", () => {
  it("uses bounded jittered backoff and resets it only after a stable open interval", () => {
    vi.useFakeTimers({ now: 0 });
    const transport = new ControlledTransport();
    const manager = createRealtimeManager({
      transport,
      idFactory: idFactory(),
      random: () => 0.5,
      reconnectBaseDelayMs: 100,
      reconnectMaxDelayMs: 250,
      stableOpenMs: 1_000,
    });

    manager.connect();
    transport.close({ reason: "network-error", reconnect: true });
    const firstDelay = latestReconnectDelay(manager);
    expect(firstDelay).toBeGreaterThanOrEqual(0);
    expect(firstDelay).toBeLessThanOrEqual(250);
    vi.advanceTimersByTime(firstDelay);
    expect(transport.connections).toHaveLength(2);

    transport.close({ reason: "network-error", reconnect: true });
    const secondDelay = latestReconnectDelay(manager);
    expect(secondDelay).toBeGreaterThanOrEqual(firstDelay);
    expect(secondDelay).toBeLessThanOrEqual(250);
    vi.advanceTimersByTime(secondDelay);
    transport.open();
    vi.advanceTimersByTime(1_000);

    transport.close({ reason: "network-error", reconnect: true });
    expect(latestReconnectDelay(manager)).toBe(firstDelay);
    manager.dispose();
  });

  it("resubscribes once after server drain and never reconnects after unauthorized close", async () => {
    vi.useFakeTimers({ now: 0 });
    const transport = new ControlledTransport();
    const manager = createRealtimeManager({
      transport,
      idFactory: idFactory(),
      random: () => 0.5,
      reconnectBaseDelayMs: 10,
      reconnectMaxDelayMs: 10,
    });
    const subscription = manager.subscribe("organizations/organization-1", vi.fn(), {
      cursor: "cursor-1",
    });

    manager.connect();
    expect(transport.connections[0]?.subscriptions).toEqual([
      {
        id: subscription.id,
        topic: "organizations/organization-1",
        cursor: "cursor-1",
      },
    ]);
    transport.open();
    await Promise.resolve();
    expect(transport.subscriptions).toEqual([
      {
        id: subscription.id,
        topic: "organizations/organization-1",
        cursor: "cursor-1",
      },
    ]);
    transport.close({ reason: "server-draining", reconnect: true });
    vi.advanceTimersByTime(latestReconnectDelay(manager));
    expect(transport.connections).toHaveLength(2);
    expect(transport.connections[1]?.subscriptions).toEqual([
      {
        id: subscription.id,
        topic: "organizations/organization-1",
        cursor: "cursor-1",
      },
    ]);
    transport.open();
    await Promise.resolve();
    await Promise.resolve();
    expect(transport.subscriptions).toHaveLength(2);

    transport.close({ reason: "unauthorized", reconnect: false, unauthorized: true });
    expect(manager.connectionState).toBe("unauthorized");
    await vi.runAllTimersAsync();
    expect(transport.connections).toHaveLength(2);
    manager.dispose();
  });

  it("suppresses reconnect duplicates with a bounded id window and isolates handler failures", () => {
    const transport = new ControlledTransport();
    const manager = createRealtimeManager({
      transport,
      idFactory: idFactory(),
      maxSeenEventIds: 2,
      knownEventTypes: ["organization.updated.v1"],
    });
    let invocation = 0;
    const handler = vi.fn(() => {
      invocation += 1;
      if (invocation === 1) {
        throw new Error("handler failed with application data");
      }
    });
    const subscription = manager.subscribe("organizations/organization-1", handler);
    manager.connect();
    transport.open();

    transport.message(domainEvent(subscription.id, EVENT_IDS[0]));
    transport.message(domainEvent(subscription.id, EVENT_IDS[0]));
    expect(handler).toHaveBeenCalledOnce();
    expect(manager.connectionState).toBe("open");
    expect(manager.lastEventId).toBe("cursor-2");
    expect(manager.diagnostics.map(({ code }) => code)).toEqual(
      expect.arrayContaining(["handler-error", "duplicate-event"]),
    );
    expect(manager.diagnostics.every((diagnostic) => !("payload" in diagnostic))).toBe(true);

    transport.message(domainEvent(subscription.id, EVENT_IDS[1], "cursor-3"));
    transport.message(domainEvent(subscription.id, EVENT_IDS[2], "cursor-4"));
    transport.message(domainEvent(subscription.id, EVENT_IDS[0], "cursor-5"));
    expect(handler).toHaveBeenCalledTimes(4);
    manager.dispose();
  });

  it("removes a revoked subscription and excludes it from later tenant re-establishment", async () => {
    const transport = new ControlledTransport();
    const manager = createRealtimeManager({
      transport,
      idFactory: idFactory(),
      knownEventTypes: ["organization.updated.v1"],
    });
    const handler = vi.fn();
    const subscription = manager.subscribe("organizations/organization-1", handler);
    manager.connect();
    transport.open();
    const revoked: SubscriptionRevokedV1 = {
      v: 1,
      id: EVENT_IDS[0],
      type: "subscription.revoked",
      correlation_id: null,
      payload: {
        subscription_id: subscription.id,
        reason: "authorization_changed",
      },
    };

    transport.message(revoked);
    expect(manager.diagnostics.map(({ code }) => code).includes("subscription-revoked")).toBe(
      true,
    );
    await manager.reestablishForTenant();
    expect(transport.disconnects).toContain("tenant-transition");
    expect(transport.connections.at(-1)?.subscriptions).toEqual([]);
    transport.open();
    transport.message(domainEvent(subscription.id, EVENT_IDS[1]));
    expect(handler).not.toHaveBeenCalled();
    manager.dispose();
  });

  it("treats identity revocation as terminal and clears every session-bound subscription", () => {
    const transport = new ControlledTransport();
    const manager = createRealtimeManager({ transport, idFactory: idFactory() });
    const first = manager.subscribe("organizations/organization-1", vi.fn());
    manager.subscribe("organizations/organization-2", vi.fn());
    manager.connect();
    transport.open();
    const connectionCount = transport.connections.length;

    transport.message({
      v: 1,
      id: EVENT_IDS[0],
      type: "subscription.revoked",
      correlation_id: null,
      payload: {
        subscription_id: first.id,
        reason: "identity_revoked",
      },
    });

    expect(manager.connectionState).toBe("unauthorized");
    expect(transport.disconnects).toContain("identity-transition");
    manager.connect();
    expect(transport.connections).toHaveLength(connectionCount);
    manager.dispose();
  });

  it("bounds subscriptions and snapshot listeners and clears authorization state on identity reset", async () => {
    const transport = new ControlledTransport();
    const manager = createRealtimeManager({
      transport,
      idFactory: idFactory(),
      maxSubscriptions: 1,
      maxSnapshotListeners: 1,
    });
    const first = manager.subscribe("organizations/organization-1", vi.fn());
    expect(() => manager.subscribe("organizations/organization-2", vi.fn())).toThrow(
      /subscription limit/iu,
    );
    const stopListening = manager.subscribeToSnapshot(vi.fn());
    expect(() => manager.subscribeToSnapshot(vi.fn())).toThrow(/listener limit/iu);
    stopListening();
    manager.connect();
    transport.open();

    await manager.resetForIdentityTransition();
    expect(transport.disconnects).toContain("identity-transition");
    expect(manager.connectionState).toBe("connecting");
    expect(transport.connections).toHaveLength(2);
    expect(transport.connections.at(-1)?.subscriptions).toEqual([]);
    first.unsubscribe();
    manager.dispose();
  });
});
