export const REALTIME_TRANSPORTS = ["websocket", "sse"] as const;
export type RealtimeTransport = (typeof REALTIME_TRANSPORTS)[number];

export type RealtimeConnectionState =
  | { readonly status: "idle" }
  | { readonly status: "connecting"; readonly transport: RealtimeTransport }
  | { readonly status: "connected"; readonly transport: RealtimeTransport }
  | {
      readonly status: "disconnected";
      readonly transport: RealtimeTransport;
      readonly reason?: string;
    };

export interface RealtimeEventEnvelope<TPayload = unknown> {
  readonly id: string;
  readonly name: string;
  readonly occurredAt: string;
  readonly payload: TPayload;
}

export type RealtimeEventListener<TPayload> = (
  event: RealtimeEventEnvelope<TPayload>,
) => void;

export interface RealtimeSubscription {
  readonly id: string;
  readonly topic: string;
  unsubscribe(): void;
}

/** Framework-neutral boundary implemented by the typed transports in T142. */
export interface RealtimeClient {
  readonly state: RealtimeConnectionState;
  subscribe<TPayload>(
    topic: string,
    listener: RealtimeEventListener<TPayload>,
  ): RealtimeSubscription;
  close(reason?: string): void;
}

export function isRealtimeConnected(
  state: RealtimeConnectionState,
): state is Extract<RealtimeConnectionState, { readonly status: "connected" }> {
  return state.status === "connected";
}
