import { AUTH_MODES } from "../client/auth.js";
import type { AuthMode } from "../client/auth.js";
import { isUnknownRecord } from "../client/type-guards.js";

export {
  CONTRACT_AGGREGATE_SHA256,
  CONTRACT_COMPATIBILITY_WINDOW,
  GENERATED_AGAINST_CONTRACT_HASH,
} from "../internal/generated/contract-metadata.js";
export type { ContractCompatibilityWindow } from "../internal/generated/contract-metadata.js";

export type CapabilityId = string;

/** Explicit OAuth/OpenID protocol roles declared independently of presented credentials. */
export const AUTH_ROLES = [
  "oauth-resource-server",
  "oauth-authorization-server",
  "openid-provider",
] as const;

export type AuthRole = (typeof AUTH_ROLES)[number];

const AUTH_ROLE_MEMBERSHIP: Readonly<Record<AuthRole, true>> = Object.freeze({
  "oauth-resource-server": true,
  "oauth-authorization-server": true,
  "openid-provider": true,
});

export interface CapabilityDescriptor {
  readonly id: CapabilityId;
  readonly compiled: boolean;
  readonly runtimeAvailable: boolean;
  readonly minimumSdkVersion: string;
  readonly authModes: readonly AuthMode[];
  readonly authRoles: readonly AuthRole[];
}

export interface CapabilityTransports {
  readonly api: string;
  readonly sse?: string;
  readonly websocket?: string;
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

export interface CompiledCapabilityDecision {
  readonly dimension: "compiled-capability";
  readonly capabilityId: CapabilityId;
  readonly compiled: boolean;
  readonly descriptor?: CapabilityDescriptor;
}

export interface RuntimeCapabilityDecision {
  readonly dimension: "runtime-availability";
  readonly capabilityId: CapabilityId;
  readonly availability: CapabilityAvailability;
  readonly available: boolean;
}

export interface ProductFlagDecision {
  readonly dimension: "product-flag";
  readonly flagId: string;
  readonly enabled: boolean;
}

export interface EntitlementDecision {
  readonly dimension: "entitlement";
  readonly entitlementId: string;
  readonly entitled: boolean;
}

export interface PermissionDecision {
  readonly dimension: "permission";
  readonly permissionId: string;
  readonly permitted: boolean;
}

export interface ProductFlagResolver<Context = unknown> {
  evaluateProductFlag(flagId: string, context: Context): Promise<boolean> | boolean;
}

export interface EntitlementResolver<Context = unknown> {
  evaluateEntitlement(entitlementId: string, context: Context): Promise<boolean> | boolean;
}

export interface PermissionResolver<Context = unknown> {
  evaluatePermission(permissionId: string, context: Context): Promise<boolean> | boolean;
}

/** Canonical runtime metadata may advertise an enabled-id list or explicit boolean values. */
export interface CapabilityRuntimeMetadata {
  readonly capabilities: readonly string[] | Readonly<Record<string, boolean>>;
}

/** Runtime metadata is independently served by the process and must agree with the build contract. */
export interface RuntimeCapabilityDocument extends CapabilityRuntimeMetadata {
  readonly profile: string;
  readonly contractHash: string;
  readonly transports: CapabilityTransports;
}

export interface VerifyCapabilityCompositionOptions {
  readonly expectedContractHash?: string;
}

export class CapabilityContractError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "CapabilityContractError";
  }
}


function requiredString(record: Record<string, unknown>, camel: string, snake = camel): string {
  const value = record[camel] ?? record[snake];
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new CapabilityContractError(`Capability manifest field ${snake} must be a non-empty string.`);
  }
  return value;
}

function optionalString(record: Record<string, unknown>, field: string): string | undefined {
  if (!Object.hasOwn(record, field)) return undefined;
  return requiredString(record, field);
}

function requiredBoolean(record: Record<string, unknown>, camel: string, snake = camel): boolean {
  const value = record[camel] ?? record[snake];
  if (typeof value !== "boolean") {
    throw new CapabilityContractError(`Capability manifest field ${snake} must be a boolean.`);
  }
  return value;
}

function parseAuthModes(value: unknown, capabilityId: string): readonly AuthMode[] {
  if (!Array.isArray(value)) {
    throw new CapabilityContractError(`Capability ${capabilityId} auth_modes must be an array.`);
  }
  const supported = new Set<string>(AUTH_MODES);
  const seen = new Set<AuthMode>();
  const modes: AuthMode[] = [];
  for (const entry of value) {
    if (typeof entry !== "string" || !supported.has(entry) || seen.has(entry as AuthMode)) {
      throw new CapabilityContractError(
        `Capability ${capabilityId} contains an unknown or duplicate authentication mode.`,
      );
    }
    const mode = entry as AuthMode;
    seen.add(mode);
    modes.push(mode);
  }
  return Object.freeze(modes);
}

function parseAuthRoles(value: unknown, capabilityId: string): readonly AuthRole[] {
  if (value === undefined) return Object.freeze([]);
  if (!Array.isArray(value)) {
    throw new CapabilityContractError(`Capability ${capabilityId} auth_roles must be an array.`);
  }
  const seen = new Set<AuthRole>();
  const roles: AuthRole[] = [];
  for (const entry of value) {
    if (
      typeof entry !== "string" ||
      AUTH_ROLE_MEMBERSHIP[entry as AuthRole] !== true ||
      seen.has(entry as AuthRole)
    ) {
      throw new CapabilityContractError(
        `Capability ${capabilityId} contains an unknown or duplicate authentication role.`,
      );
    }
    const role = entry as AuthRole;
    seen.add(role);
    roles.push(role);
  }
  return Object.freeze(roles);
}

/** Parses the canonical snake_case contract (and the equivalent SDK camelCase object) strictly. */
export function parseCapabilityManifest(input: unknown): CapabilityManifest {
  if (!isUnknownRecord(input)) {
    throw new CapabilityContractError("Capability manifest must be an object.");
  }
  if (!Array.isArray(input.capabilities)) {
    throw new CapabilityContractError("Capability manifest capabilities must be an array.");
  }
  const ids = new Set<string>();
  const capabilities = input.capabilities.map((value): CapabilityDescriptor => {
    if (!isUnknownRecord(value)) {
      throw new CapabilityContractError("Capability descriptor must be an object.");
    }
    const id = requiredString(value, "id");
    if (ids.has(id)) throw new CapabilityContractError(`Capability id ${id} is duplicated.`);
    ids.add(id);
    const authModes = parseAuthModes(value.authModes ?? value.auth_modes, id);
    const authRoles = parseAuthRoles(value.authRoles ?? value.auth_roles, id);
    return Object.freeze({
      id,
      compiled: requiredBoolean(value, "compiled"),
      runtimeAvailable: requiredBoolean(value, "runtimeAvailable", "runtime_available"),
      minimumSdkVersion: requiredString(value, "minimumSdkVersion", "minimum_sdk_version"),
      authModes,
      authRoles,
    });
  });
  const transportsValue = input.transports;
  if (!isUnknownRecord(transportsValue)) {
    throw new CapabilityContractError("Capability manifest transports must be an object.");
  }
  const sse = optionalString(transportsValue, "sse");
  const websocket = optionalString(transportsValue, "websocket");
  const transports: CapabilityTransports = Object.freeze({
    api: requiredString(transportsValue, "api"),
    ...(sse === undefined ? {} : { sse }),
    ...(websocket === undefined ? {} : { websocket }),
  });
  return Object.freeze({
    schemaVersion: requiredString(input, "schemaVersion", "schema_version"),
    serviceVersion: requiredString(input, "serviceVersion", "service_version"),
    profile: requiredString(input, "profile"),
    contractHash: requiredString(input, "contractHash", "contract_hash"),
    capabilities: Object.freeze(capabilities),
    transports,
  });
}

function parseCapabilityTransports(input: unknown, label: string): CapabilityTransports {
  if (!isUnknownRecord(input)) {
    throw new CapabilityContractError(`${label} transports must be an object.`);
  }
  const sse = optionalString(input, "sse");
  const websocket = optionalString(input, "websocket");
  return Object.freeze({
    api: requiredString(input, "api"),
    ...(sse === undefined ? {} : { sse }),
    ...(websocket === undefined ? {} : { websocket }),
  });
}

/** Strictly parses the process-owned `/api/_meta` fields used for runtime composition. */
export function parseRuntimeCapabilityDocument(input: unknown): RuntimeCapabilityDocument {
  if (!isUnknownRecord(input)) {
    throw new CapabilityContractError("Runtime capability metadata must be an object.");
  }
  const capabilities = input.capabilities;
  if (!Array.isArray(capabilities) && !isUnknownRecord(capabilities)) {
    throw new CapabilityContractError(
      "Runtime capabilities must be an id array or boolean record.",
    );
  }
  return Object.freeze({
    profile: requiredString(input, "profile"),
    contractHash: requiredString(input, "contractHash", "contract_hash"),
    capabilities: capabilities as
      | readonly string[]
      | Readonly<Record<string, boolean>>,
    transports: parseCapabilityTransports(input.transports, "Runtime capability metadata"),
  });
}

function equalTransports(left: CapabilityTransports, right: CapabilityTransports): boolean {
  return (
    left.api === right.api &&
    left.sse === right.sse &&
    left.websocket === right.websocket
  );
}

/**
 * Joins build-time structural evidence to independently reported process availability.
 * A mismatch fails closed instead of inferring a feature from bundled source.
 */
export function createVerifiedCapabilityRegistry(
  manifestInput: unknown,
  runtimeInput: unknown,
  options: VerifyCapabilityCompositionOptions = {},
): CapabilityRegistry {
  const manifest = parseCapabilityManifest(manifestInput);
  const runtime = parseRuntimeCapabilityDocument(runtimeInput);
  if (
    options.expectedContractHash !== undefined &&
    manifest.contractHash !== options.expectedContractHash
  ) {
    throw new CapabilityContractError(
      `Capability manifest contract ${manifest.contractHash} does not match this web build.`,
    );
  }
  if (runtime.profile !== manifest.profile) {
    throw new CapabilityContractError(
      `Runtime profile ${runtime.profile} does not match capability profile ${manifest.profile}.`,
    );
  }
  if (runtime.contractHash !== manifest.contractHash) {
    throw new CapabilityContractError(
      `Runtime contract ${runtime.contractHash} does not match capability contract ${manifest.contractHash}.`,
    );
  }
  if (!equalTransports(runtime.transports, manifest.transports)) {
    throw new CapabilityContractError(
      "Runtime transports do not match the capability manifest.",
    );
  }
  if (
    manifest.transports.sse !== undefined &&
    manifest.transports.sse !== "/realtime/events"
  ) {
    throw new CapabilityContractError(
      "The canonical SSE transport path is /realtime/events.",
    );
  }
  if (
    manifest.transports.websocket !== undefined &&
    manifest.transports.websocket !== "/realtime/ws"
  ) {
    throw new CapabilityContractError(
      "The canonical WebSocket transport path is /realtime/ws.",
    );
  }
  const descriptors = new Map(
    manifest.capabilities.map((descriptor) => [descriptor.id, descriptor] as const),
  );
  const runtimeEntries = Array.isArray(runtime.capabilities)
    ? runtime.capabilities.map((id) => [id, true] as const)
    : Object.entries(runtime.capabilities);
  for (const [id, available] of runtimeEntries) {
    const descriptor = descriptors.get(id);
    if (descriptor === undefined) {
      throw new CapabilityContractError(
        `Runtime metadata advertises unknown capability ${id}.`,
      );
    }
    if (available && !descriptor.compiled) {
      throw new CapabilityContractError(
        `Runtime metadata advertises uncompiled capability ${id}.`,
      );
    }
  }
  return new CapabilityRegistry(manifest, runtime);
}

/** Distinguishes build-time absence from a compiled capability that is unavailable at runtime. */
export function getCapabilityAvailability(
  capability: Pick<CapabilityDescriptor, "compiled" | "runtimeAvailable">,
): CapabilityAvailability {
  if (!capability.compiled) return "not-compiled";
  return capability.runtimeAvailable ? "available" : "runtime-unavailable";
}

export function isCapabilityAvailable(
  capability: Pick<CapabilityDescriptor, "compiled" | "runtimeAvailable">,
): boolean {
  return capability.compiled && capability.runtimeAvailable;
}

export class CapabilityRegistry {
  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private readonly descriptors = new Map<CapabilityId, CapabilityDescriptor>();
  private readonly listeners = new Set<() => void>();
  private readonly runtime = new Map<CapabilityId, boolean>();
  private readonly compiledDecisions = new Map<CapabilityId, CompiledCapabilityDecision>();
  private readonly runtimeDecisions = new Map<CapabilityId, RuntimeCapabilityDecision>();

  constructor(readonly manifest: CapabilityManifest, runtimeMetadata?: CapabilityRuntimeMetadata) {
    for (const descriptor of manifest.capabilities) {
      this.descriptors.set(descriptor.id, descriptor);
      this.runtime.set(descriptor.id, descriptor.runtimeAvailable);
    }
    if (runtimeMetadata !== undefined) this.applyRuntimeMetadata(runtimeMetadata);
    this.rebuildDecisions();
  }

  resolveCompiled(capabilityId: CapabilityId): CompiledCapabilityDecision {
    const existing = this.compiledDecisions.get(capabilityId);
    if (existing !== undefined) return existing;
    const absent = Object.freeze({
      dimension: "compiled-capability" as const,
      capabilityId,
      compiled: false,
    });
    this.compiledDecisions.set(capabilityId, absent);
    return absent;
  }

  resolveRuntimeAvailability(capabilityId: CapabilityId): RuntimeCapabilityDecision {
    const existing = this.runtimeDecisions.get(capabilityId);
    if (existing !== undefined) return existing;
    const absent = Object.freeze({
      dimension: "runtime-availability" as const,
      capabilityId,
      availability: "not-compiled" as const,
      available: false,
    });
    this.runtimeDecisions.set(capabilityId, absent);
    return absent;
  }

  updateRuntimeMetadata(metadata: CapabilityRuntimeMetadata): void {
    const next = this.parseRuntimeMetadata(metadata);
    let changed = next.size !== this.runtime.size;
    if (!changed) {
      for (const [id, available] of next) {
        if (this.runtime.get(id) !== available) {
          changed = true;
          break;
        }
      }
    }
    if (!changed) return;
    this.runtime.clear();
    for (const [id, available] of next) this.runtime.set(id, available);
    this.rebuildDecisions();
    for (const listener of this.listeners) listener();
  }

  private applyRuntimeMetadata(metadata: CapabilityRuntimeMetadata): void {
    const next = this.parseRuntimeMetadata(metadata);
    this.runtime.clear();
    for (const [id, available] of next) this.runtime.set(id, available);
  }

  private parseRuntimeMetadata(metadata: CapabilityRuntimeMetadata): Map<CapabilityId, boolean> {
    const values = metadata.capabilities;
    const next = new Map<CapabilityId, boolean>();
    if (Array.isArray(values)) {
      const availableIds = new Set(values);
      for (const id of availableIds) {
        if (typeof id !== "string" || id.trim().length === 0) {
          throw new CapabilityContractError("Runtime capability ids must be non-empty strings.");
        }
      }
      for (const id of this.descriptors.keys()) next.set(id, availableIds.has(id));
      return next;
    }
    if (!isUnknownRecord(values)) {
      throw new CapabilityContractError(
        "Runtime capabilities must be an id array or boolean record.",
      );
    }
    for (const id of this.descriptors.keys()) next.set(id, false);
    for (const [id, available] of Object.entries(values)) {
      if (typeof available !== "boolean" || id.trim().length === 0) {
        throw new CapabilityContractError("Runtime capability records require boolean values.");
      }
      if (this.descriptors.has(id)) next.set(id, available);
    }
    return next;
  }

  private rebuildDecisions(): void {
    this.compiledDecisions.clear();
    this.runtimeDecisions.clear();
    for (const descriptor of this.descriptors.values()) {
      const compiled = Object.freeze({
        dimension: "compiled-capability" as const,
        capabilityId: descriptor.id,
        compiled: descriptor.compiled,
        descriptor,
      });
      const availability: CapabilityAvailability = !descriptor.compiled
        ? "not-compiled"
        : this.runtime.get(descriptor.id) === true
          ? "available"
          : "runtime-unavailable";
      this.compiledDecisions.set(descriptor.id, compiled);
      this.runtimeDecisions.set(
        descriptor.id,
        Object.freeze({
          dimension: "runtime-availability",
          capabilityId: descriptor.id,
          availability,
          available: availability === "available",
        }),
      );
    }
  }
}

export function createCapabilityRegistry(
  manifest: unknown,
  runtimeMetadata?: CapabilityRuntimeMetadata,
): CapabilityRegistry {
  return new CapabilityRegistry(parseCapabilityManifest(manifest), runtimeMetadata);
}

export function requireCompiledCapability(decision: CompiledCapabilityDecision): CapabilityDescriptor {
  if (!decision.compiled || decision.descriptor === undefined) {
    throw new Error(`Capability ${decision.capabilityId} is not structurally compiled.`);
  }
  return decision.descriptor;
}

export function requireRuntimeCapability(decision: RuntimeCapabilityDecision): void {
  if (!decision.available) {
    throw new Error(
      `Capability ${decision.capabilityId} is not runtime available (${decision.availability}).`,
    );
  }
}

export async function resolveProductFlag<Context>(
  resolver: ProductFlagResolver<Context>,
  flagId: string,
  context: Context,
): Promise<ProductFlagDecision> {
  return Object.freeze({
    dimension: "product-flag",
    flagId,
    enabled: await resolver.evaluateProductFlag(flagId, context),
  });
}

export async function resolveEntitlement<Context>(
  resolver: EntitlementResolver<Context>,
  entitlementId: string,
  context: Context,
): Promise<EntitlementDecision> {
  return Object.freeze({
    dimension: "entitlement",
    entitlementId,
    entitled: await resolver.evaluateEntitlement(entitlementId, context),
  });
}

export async function resolvePermission<Context>(
  resolver: PermissionResolver<Context>,
  permissionId: string,
  context: Context,
): Promise<PermissionDecision> {
  return Object.freeze({
    dimension: "permission",
    permissionId,
    permitted: await resolver.evaluatePermission(permissionId, context),
  });
}

export function requireProductFlag(decision: ProductFlagDecision): void {
  if (!decision.enabled) throw new Error(`Product flag ${decision.flagId} is disabled.`);
}

export function requireEntitlement(decision: EntitlementDecision): void {
  if (!decision.entitled) throw new Error(`Entitlement ${decision.entitlementId} is absent.`);
}

export function requirePermission(decision: PermissionDecision): void {
  if (!decision.permitted) throw new Error(`Permission ${decision.permissionId} is denied.`);
}
