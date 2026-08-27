import { useCallback, useSyncExternalStore } from "react";

import type {
  CapabilityId,
  CapabilityRegistry,
  CompiledCapabilityDecision,
  RuntimeCapabilityDecision,
} from "../capabilities/index.js";

/** Structural build composition does not change at runtime and needs no subscription. */
export function useCompiledCapability(
  registry: CapabilityRegistry,
  capabilityId: CapabilityId,
): CompiledCapabilityDecision {
  return registry.resolveCompiled(capabilityId);
}

/** Subscribes only to runtime availability; flags, entitlements, and permissions stay separate. */
export function useRuntimeCapability(
  registry: CapabilityRegistry,
  capabilityId: CapabilityId,
): RuntimeCapabilityDecision {
  const getSnapshot = useCallback(
    () => registry.resolveRuntimeAvailability(capabilityId),
    [capabilityId, registry],
  );
  return useSyncExternalStore(registry.subscribe, getSnapshot, getSnapshot);
}
