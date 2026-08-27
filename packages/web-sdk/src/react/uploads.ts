import { useEffect, useRef, useSyncExternalStore } from "react";

import type { UploadCoordinator, UploadState } from "../uploads/index.js";

export interface UseUploadCoordinatorOptions {
  readonly autoStart?: boolean;
  readonly disposeOnUnmount?: boolean;
}

/** Subscribes to a coordinator snapshot; all transfer correctness remains in the coordinator. */
export function useUploadState(coordinator: UploadCoordinator): UploadState {
  return useSyncExternalStore(
    coordinator.subscribe,
    coordinator.getSnapshot,
    coordinator.getSnapshot,
  );
}

/** Starts and owns coordinator cleanup without reimplementing transport behavior in React. */
export function useUploadCoordinator(
  coordinator: UploadCoordinator,
  options: UseUploadCoordinatorOptions = {},
): UploadState {
  const state = useUploadState(coordinator);
  const autoStart = options.autoStart ?? true;
  const disposeOnUnmount = options.disposeOnUnmount ?? true;
  const lifecycle = useRef(0);
  const currentCoordinator = useRef(coordinator);

  useEffect(() => {
    currentCoordinator.current = coordinator;
    lifecycle.current += 1;
    if (autoStart && coordinator.state.status !== "disposed") void coordinator.start();
    return () => {
      if (!disposeOnUnmount) return;
      lifecycle.current += 1;
      const cleanupGeneration = lifecycle.current;
      queueMicrotask(() => {
        // React Strict Mode's immediate setup after its cleanup invalidates this disposal.
        if (
          lifecycle.current === cleanupGeneration ||
          currentCoordinator.current !== coordinator
        ) {
          void coordinator.dispose();
        }
      });
    };
  }, [autoStart, coordinator, disposeOnUnmount]);

  return state;
}
