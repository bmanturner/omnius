export type EphemeralLocalStateCategory =
  | "editor-workbench"
  | "transient-workflow"
  | "panel-layout"
  | "local-selection";

export type DurableLocalStateCategory =
  | "editor-workbench"
  | "panel-layout"
  | "safe-preference";

export interface EphemeralLocalStateOwnership {
  readonly key: string;
  readonly owner: "client-local";
  readonly durability: "ephemeral";
  readonly category: EphemeralLocalStateCategory;
  readonly rationale: string;
}

export interface DurableLocalStateOwnership {
  readonly key: string;
  readonly owner: "client-local";
  readonly durability: "durable-local";
  readonly category: DurableLocalStateCategory;
  readonly rationale: string;
  readonly schemaVersion: number;
}

export type ForbiddenLocalStateOwner =
  | "remote-resource"
  | "server-resource"
  | "server-truth"
  | "authenticated-principal"
  | "auth-secret"
  | "permission-cache";

export interface ForbiddenLocalStateOwnership {
  readonly key: string;
  readonly owner: ForbiddenLocalStateOwner;
  readonly rationale?: string;
}

export type LocalStateOwnershipDescriptor =
  | EphemeralLocalStateOwnership
  | DurableLocalStateOwnership;

export type StateOwnershipDescriptor =
  | LocalStateOwnershipDescriptor
  | ForbiddenLocalStateOwnership;

const ephemeralCategories: Readonly<Record<EphemeralLocalStateCategory, true>> = Object.freeze({
  "editor-workbench": true,
  "transient-workflow": true,
  "panel-layout": true,
  "local-selection": true,
});

const durableCategories: Readonly<Record<DurableLocalStateCategory, true>> = Object.freeze({
  "editor-workbench": true,
  "panel-layout": true,
  "safe-preference": true,
});

const forbiddenOwnerReasons: Readonly<Record<ForbiddenLocalStateOwner, string>> = Object.freeze({
  "remote-resource": "Remote resources belong in the query cache, not client-local state.",
  "server-resource": "Server resources belong in the query cache, not client-local state.",
  "server-truth": "Durable server truth must remain owned by the backend.",
  "authenticated-principal": "The authenticated principal is a server resource, not local state.",
  "auth-secret": "Authentication secrets must not be owned by browser state.",
  "permission-cache": "Permissions must not be duplicated into a second client cache.",
});

function assertNonEmptyDescriptorText(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`Local-state ${label} must not be empty.`);
  }
}

function localStateOwnerRejection(owner: unknown): string {
  switch (owner) {
    case "remote-resource":
    case "server-resource":
    case "server-truth":
    case "authenticated-principal":
    case "auth-secret":
    case "permission-cache":
      return forbiddenOwnerReasons[owner];
    default:
      return "Only explicitly client-local state may use a local store.";
  }
}

function isEphemeralCategory(value: unknown): value is EphemeralLocalStateCategory {
  return typeof value === "string" && Object.hasOwn(ephemeralCategories, value);
}

function isDurableCategory(value: unknown): value is DurableLocalStateCategory {
  return typeof value === "string" && Object.hasOwn(durableCategories, value);
}

/**
 * Runtime policy assertion intended for store construction and development checks. It returns a
 * normalized descriptor so unvalidated or extra input cannot flow into store construction.
 */
export function assertLocalStateOwnership(
  descriptor: unknown,
): Readonly<LocalStateOwnershipDescriptor> {
  if (typeof descriptor !== "object" || descriptor === null || Array.isArray(descriptor)) {
    throw new TypeError("Local-state ownership must be an object.");
  }
  const key = "key" in descriptor ? descriptor.key : undefined;
  const owner = "owner" in descriptor ? descriptor.owner : undefined;
  const rationale = "rationale" in descriptor ? descriptor.rationale : undefined;
  assertNonEmptyDescriptorText(key, "key");
  if (owner !== "client-local") {
    throw new TypeError(localStateOwnerRejection(owner));
  }
  assertNonEmptyDescriptorText(rationale, "rationale");

  const durability = "durability" in descriptor ? descriptor.durability : undefined;
  const category = "category" in descriptor ? descriptor.category : undefined;
  if (durability === "ephemeral") {
    if (!isEphemeralCategory(category)) {
      throw new TypeError(
        `Category ${String(category)} is not allowed for ephemeral local state.`,
      );
    }
    return Object.freeze({
      key,
      owner,
      durability,
      category,
      rationale,
    });
  }
  if (durability !== "durable-local") {
    throw new TypeError(`Durability ${String(durability)} is not allowed.`);
  }
  if (!isDurableCategory(category)) {
    throw new TypeError(
      `Category ${String(category)} is not allowed for durable local state.`,
    );
  }
  const schemaVersion = "schemaVersion" in descriptor ? descriptor.schemaVersion : undefined;
  if (
    typeof schemaVersion !== "number" ||
    !Number.isSafeInteger(schemaVersion) ||
    schemaVersion < 1
  ) {
    throw new TypeError("Durable local state requires a positive integer schemaVersion.");
  }
  return Object.freeze({
    key,
    owner,
    durability,
    category,
    rationale,
    schemaVersion,
  });
}

export interface VersionedLocalStateEnvelope {
  readonly schemaVersion: number;
  readonly value: unknown;
}

export type LocalStateRestoreResult<TValue> =
  | {
      readonly status: "current";
      readonly schemaVersion: number;
      readonly value: TValue;
    }
  | {
      readonly status: "migrated";
      readonly schemaVersion: number;
      readonly previousSchemaVersion: number;
      readonly value: TValue;
    }
  | {
      readonly status: "discarded";
      readonly reason:
        | "malformed-envelope"
        | "invalid-current-value"
        | "future-version"
        | "migration-unavailable"
        | "migration-failed"
        | "invalid-migrated-value";
    };

export interface RestoreLocalStateOptions<TValue> {
  readonly currentSchemaVersion: number;
  /** Decode and validate without throwing. Invalid values return undefined. */
  readonly decode: (value: unknown) => TValue | undefined;
  /** Migrate directly to currentSchemaVersion. Absence deliberately discards stale state. */
  readonly migrate?: (
    value: unknown,
    previousSchemaVersion: number,
    currentSchemaVersion: number,
  ) => unknown;
}
function readVersionedLocalStateEnvelope(
  envelope: unknown,
): VersionedLocalStateEnvelope | undefined {
  try {
    if (
      typeof envelope !== "object" ||
      envelope === null ||
      Array.isArray(envelope) ||
      !("schemaVersion" in envelope) ||
      !("value" in envelope) ||
      !Object.hasOwn(envelope, "schemaVersion") ||
      !Object.hasOwn(envelope, "value")
    ) {
      return undefined;
    }
    const schemaVersion = envelope.schemaVersion;
    if (
      typeof schemaVersion !== "number" ||
      !Number.isSafeInteger(schemaVersion) ||
      schemaVersion < 1
    ) {
      return undefined;
    }
    return { schemaVersion, value: envelope.value };
  } catch {
    return undefined;
  }
}

/** Restores current local state, migrates an older version, or safely discards unusable state. */
export function restoreLocalState<TValue>(
  envelope: unknown,
  options: Readonly<RestoreLocalStateOptions<TValue>>,
): LocalStateRestoreResult<TValue> {
  if (!Number.isSafeInteger(options.currentSchemaVersion) || options.currentSchemaVersion < 1) {
    throw new TypeError("currentSchemaVersion must be a positive integer.");
  }
  const stored = readVersionedLocalStateEnvelope(envelope);
  if (stored === undefined) {
    return Object.freeze({ status: "discarded", reason: "malformed-envelope" });
  }

  if (stored.schemaVersion > options.currentSchemaVersion) {
    return Object.freeze({ status: "discarded", reason: "future-version" });
  }
  if (stored.schemaVersion === options.currentSchemaVersion) {
    let decoded: TValue | undefined;
    try {
      decoded = options.decode(stored.value);
    } catch {
      decoded = undefined;
    }
    return decoded === undefined
      ? Object.freeze({ status: "discarded", reason: "invalid-current-value" })
      : Object.freeze({
          status: "current",
          schemaVersion: options.currentSchemaVersion,
          value: decoded,
        });
  }
  if (options.migrate === undefined) {
    return Object.freeze({ status: "discarded", reason: "migration-unavailable" });
  }

  let migrated: unknown;
  try {
    migrated = options.migrate(
      stored.value,
      stored.schemaVersion,
      options.currentSchemaVersion,
    );
  } catch {
    return Object.freeze({ status: "discarded", reason: "migration-failed" });
  }
  let decoded: TValue | undefined;
  try {
    decoded = options.decode(migrated);
  } catch {
    decoded = undefined;
  }
  if (decoded === undefined) {
    return Object.freeze({ status: "discarded", reason: "invalid-migrated-value" });
  }
  return Object.freeze({
    status: "migrated",
    schemaVersion: options.currentSchemaVersion,
    previousSchemaVersion: stored.schemaVersion,
    value: decoded,
  });
}
