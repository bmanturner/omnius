// @vitest-environment jsdom

import { act, render } from "@testing-library/react";
import { createElement } from "react";
import type { ReactElement } from "react";
import { describe, expect, it, vi } from "vitest";

import type {
  ClientRealtimeWireMessage,
  DomainEventV1,
  ServerRealtimeWireMessage,
} from "../src/internal/generated/realtime.js";
import {
  RealtimeProvider,
  useEvent,
} from "../src/react/realtime.js";
import type {
  RealtimeCommandOptions,
  RealtimeConnectionState,
  RealtimeDiagnostic,
  RealtimeDisconnectReason,
  RealtimeEventHandler,
  RealtimeLifecycleContext,
  RealtimeManager,
  RealtimeSnapshot,
  RealtimeSubscribeOptions,
  RealtimeSubscription,
  RealtimeTransportPort,
} from "../src/realtime/index.js";

const EVENT_IDS = [
  "01890f47-7e7a-7c8a-9abc-1234567890ab",
  "01890f47-7e7a-7c8a-9abc-1234567890ac",
] as const;
const SUBSCRIPTION_ID = "01890f47-7e7a-7c8a-9abc-1234567890b1";

class ControlledRealtimeManager implements RealtimeManager {
  readonly lastEventId = null;
  readonly diagnostics: readonly RealtimeDiagnostic[] = [];
  readonly subscriptions = new Map<
    string,
    { readonly topic: string; readonly handler: RealtimeEventHandler }
  >();
  connectionState: RealtimeConnectionState = "idle";
  connectCount = 0;
  disconnectCount = 0;
  disposeCount = 0;
  subscribeCount = 0;
  unsubscribeCount = 0;
  subscriptionGeneration = 0;
  #nextSubscription = 0;
  readonly #snapshotListeners = new Set<() => void>();

  connect(): void {
    this.connectCount += 1;
  }

  disconnect(_reason?: RealtimeDisconnectReason): void {
    this.disconnectCount += 1;
  }

  dispose(): void {
    this.disposeCount += 1;
    this.subscriptions.clear();
  }

  subscribe(
    topic: string,
    handler: RealtimeEventHandler,
    _options?: RealtimeSubscribeOptions,
  ): RealtimeSubscription {
    this.subscribeCount += 1;
    this.#nextSubscription += 1;
    const id = `${SUBSCRIPTION_ID}:${this.#nextSubscription}`;
    this.subscriptions.set(id, { topic, handler });
    let active = true;
    return {
      id,
      topic,
      unsubscribe: () => {
        if (!active) {
          return;
        }
        active = false;
        this.unsubscribe(id);
      },
    };
  }

  unsubscribe(subscriptionId: string): void {
    if (this.subscriptions.delete(subscriptionId)) {
      this.unsubscribeCount += 1;
    }
  }

  async sendCommand(
    _command: ClientRealtimeWireMessage,
    _options?: RealtimeCommandOptions,
  ): Promise<ServerRealtimeWireMessage> {
    throw new Error("Commands are not used by this React test fake");
  }

  getSnapshot(): RealtimeSnapshot {
    return {
      connectionState: this.connectionState,
      lastEventId: this.lastEventId,
      subscriptionGeneration: this.subscriptionGeneration,
      diagnostics: this.diagnostics,
    };
  }

  subscribeToSnapshot(listener: () => void): () => void {
    this.#snapshotListeners.add(listener);
    return () => {
      this.#snapshotListeners.delete(listener);
    };
  }

  async resetForIdentityTransition(_context?: RealtimeLifecycleContext): Promise<void> {}

  async reestablishForTenant(_context?: RealtimeLifecycleContext): Promise<void> {}

  advanceSubscriptionGeneration(): void {
    this.subscriptionGeneration += 1;
    for (const listener of this.#snapshotListeners) {
      listener();
    }
  }

  publish(event: DomainEventV1): void {
    for (const subscription of this.subscriptions.values()) {
      if (subscription.topic === event.payload.topic) {
        subscription.handler(event);
      }
    }
  }
}

function event(id: string): DomainEventV1 {
  return {
    v: 1,
    id,
    type: "organization.updated.v1",
    correlation_id: null,
    payload: {
      subscription_id: SUBSCRIPTION_ID,
      topic: "organizations/organization-1",
      cursor: "cursor-2",
      data: { organization_id: "organization-1" },
    },
  };
}

function EventObserver(props: { readonly handler: RealtimeEventHandler }): ReactElement | null {
  useEvent("organizations/organization-1", props.handler);
  return null;
}

describe("React realtime adapter", () => {
  it("uses the latest handler, reestablishes after authority reset, and cleans up", () => {
    const manager = new ControlledRealtimeManager();
    const firstHandler = vi.fn();
    const latestHandler = vi.fn();
    const view = render(
      createElement(
        RealtimeProvider,
        { manager, autoConnect: false },
        createElement(EventObserver, { handler: firstHandler }),
      ),
    );

    act(() => manager.publish(event(EVENT_IDS[0])));
    expect(firstHandler).toHaveBeenCalledOnce();
    view.rerender(
      createElement(
        RealtimeProvider,
        { manager, autoConnect: false },
        createElement(EventObserver, { handler: latestHandler }),
      ),
    );
    expect(manager.subscribeCount).toBe(1);
    act(() => manager.advanceSubscriptionGeneration());
    expect(manager.subscribeCount).toBe(2);
    expect(manager.unsubscribeCount).toBe(1);
    expect(manager.subscriptions.size).toBe(1);

    act(() => manager.publish(event(EVENT_IDS[1])));
    expect(firstHandler).toHaveBeenCalledOnce();
    expect(latestHandler).toHaveBeenCalledOnce();

    view.unmount();
    expect(manager.unsubscribeCount).toBe(2);
    expect(manager.subscriptions.size).toBe(0);
    expect(manager.disposeCount).toBe(0);
  });

  it("connects and disposes only a manager created by the provider", async () => {
    const manager = new ControlledRealtimeManager();
    const transport: RealtimeTransportPort = {
      kind: "websocket",
      connect() {},
      disconnect() {},
    };
    const factory = vi.fn(() => manager);
    const view = render(
      createElement(RealtimeProvider, {
        configuration: { transport, idFactory: () => SUBSCRIPTION_ID },
        factory,
      }),
    );

    expect(factory).toHaveBeenCalledOnce();
    expect(manager.connectCount).toBe(1);
    view.unmount();
    await act(async () => {
      await Promise.resolve();
    });
    expect(manager.disposeCount).toBe(1);
  });
});
