import type {
  CrossTabAuthSignal,
  CrossTabAuthSignalPort,
  IdentityTransitionContext,
  IdentityTransitionLifecycle,
} from "../auth/index.js";

export interface ValueRecorder<TValue> {
  record(value: TValue): void;
  snapshot(): readonly TValue[];
  clear(): void;
}

/** Creates an isolated recorder whose snapshots cannot mutate the captured sequence. */
export function createValueRecorder<TValue>(): ValueRecorder<TValue> {
  const values: TValue[] = [];
  return Object.freeze({
    record(value: TValue): void {
      values.push(value);
    },
    snapshot(): readonly TValue[] {
      return Object.freeze(values.slice());
    },
    clear(): void {
      values.length = 0;
    },
  });
}

export interface Deferred<TValue> {
  readonly promise: Promise<TValue>;
  resolve(value: TValue | PromiseLike<TValue>): void;
  reject(reason?: unknown): void;
}

/** Deterministic promise control for focused SDK concurrency tests. */
export function createDeferred<TValue>(): Deferred<TValue> {
  let resolvePromise: (value: TValue | PromiseLike<TValue>) => void = () => undefined;
  let rejectPromise: (reason?: unknown) => void = () => undefined;
  const promise = new Promise<TValue>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return Object.freeze({
    promise,
    resolve: resolvePromise,
    reject: rejectPromise,
  });
}

export interface AuthSignalTestBus {
  createPort(): CrossTabAuthSignalPort;
  snapshot(): readonly CrossTabAuthSignal[];
}

/**
 * In-memory BroadcastChannel test double. It records only the credential-free public signal type.
 */
export function createAuthSignalTestBus(): AuthSignalTestBus {
  interface TestPort {
    readonly listeners: Set<(signal: unknown) => void>;
    closed: boolean;
  }
  const ports = new Set<TestPort>();
  const signals: CrossTabAuthSignal[] = [];

  return Object.freeze({
    createPort(): CrossTabAuthSignalPort {
      const testPort: TestPort = {
        listeners: new Set(),
        closed: false,
      };
      ports.add(testPort);
      return Object.freeze({
        publish(signal: CrossTabAuthSignal): void {
          if (testPort.closed) {
            throw new Error("The auth signal test port is closed.");
          }
          signals.push(Object.freeze({ ...signal }));
          for (const peer of ports) {
            if (peer === testPort || peer.closed) {
              continue;
            }
            for (const listener of peer.listeners) {
              listener(signal);
            }
          }
        },
        subscribe(listener: (signal: unknown) => void): () => void {
          if (testPort.closed) {
            throw new Error("The auth signal test port is closed.");
          }
          testPort.listeners.add(listener);
          return () => {
            testPort.listeners.delete(listener);
          };
        },
        close(): void {
          testPort.closed = true;
          testPort.listeners.clear();
          ports.delete(testPort);
        },
      });
    },
    snapshot(): readonly CrossTabAuthSignal[] {
      return Object.freeze(signals.slice());
    },
  });
}

export interface IdentityTransitionRecorder extends IdentityTransitionLifecycle {
  snapshot(): readonly IdentityTransitionContext[];
}

export function createIdentityTransitionRecorder(): IdentityTransitionRecorder {
  const transitions: IdentityTransitionContext[] = [];
  return Object.freeze({
    transition(context: IdentityTransitionContext): void {
      transitions.push(Object.freeze({ ...context }));
    },
    snapshot(): readonly IdentityTransitionContext[] {
      return Object.freeze(transitions.slice());
    },
  });
}
