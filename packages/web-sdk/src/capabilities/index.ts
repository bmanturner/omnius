import type { AuthMode } from "../auth/index.js";

export {
  CONTRACT_AGGREGATE_SHA256,
  CONTRACT_COMPATIBILITY_WINDOW,
  GENERATED_AGAINST_CONTRACT_HASH,
} from "../internal/generated/contract-metadata.js";
export type { ContractCompatibilityWindow } from "../internal/generated/contract-metadata.js";

export type CapabilityId = string;

export interface CapabilityDescriptor {
  readonly id: CapabilityId;
  readonly compiled: boolean;
  readonly runtimeAvailable: boolean;
  readonly minimumSdkVersion: string;
  readonly authModes: readonly AuthMode[];
}

export interface CapabilityTransports {
  readonly api: string;
  readonly sse: string;
  readonly websocket: string;
}

export interface CapabilityManifest {
  readonly schemaVersion: string;
  readonly serviceVersion: string;
  readonly profile: string;
  readonly contractHash: string;
  readonly capabilities: readonly CapabilityDescriptor[];
  readonly transports: CapabilityTransports;
}

export type CapabilityAvailability = "available" | "not-compiled" | "runtime-unavailable";

/** Distinguishes build-time absence from a compiled capability that is unavailable at runtime. */
export function getCapabilityAvailability(
  capability: Pick<CapabilityDescriptor, "compiled" | "runtimeAvailable">,
): CapabilityAvailability {
  if (!capability.compiled) {
    return "not-compiled";
  }
  return capability.runtimeAvailable ? "available" : "runtime-unavailable";
}

export function isCapabilityAvailable(
  capability: Pick<CapabilityDescriptor, "compiled" | "runtimeAvailable">,
): boolean {
  return capability.compiled && capability.runtimeAvailable;
}
