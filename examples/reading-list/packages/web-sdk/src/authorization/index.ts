export type PermissionId = string;

export interface PermissionDescriptor {
  readonly id: PermissionId;
  readonly action: string;
  readonly resource: string;
  readonly group: string;
  readonly description: string;
  readonly deprecated: boolean;
  readonly replacement: PermissionId | null;
}

/** All `allOf` permissions and at least one present `anyOf` permission are required. */
export interface PermissionRequirement {
  readonly allOf?: readonly PermissionId[];
  readonly anyOf?: readonly PermissionId[];
}

export type PresentationResourceContext = Readonly<
  Record<string, string | number | boolean | null>
>;

export interface PresentationPermissionGrant {
  readonly permission: PermissionId;
  readonly context: PresentationResourceContext;
}

/**
 * A presentation-only permission view for hiding, disabling, redirecting, or explaining UI.
 *
 * It is never an authorization or security boundary. Every backend operation must authorize
 * independently even when this snapshot says that an action is available.
 */
export interface PresentationAuthorizationSnapshot {
  readonly permissions: readonly PermissionId[];
  readonly resourcePermissions: readonly PresentationPermissionGrant[];
}

function validatePermission(permission: PermissionId): PermissionId {
  if (permission.length === 0 || permission.trim() !== permission) {
    throw new TypeError("Presentation permission IDs must be non-empty trimmed values.");
  }
  return permission;
}

/** Creates an immutable UX-only permission snapshot from public backend presentation data. */
export function createPresentationAuthorization(
  permissions: readonly PermissionId[],
  resourcePermissions: readonly PresentationPermissionGrant[] = [],
): Readonly<PresentationAuthorizationSnapshot> {
  const uniquePermissions = new Set<PermissionId>();
  for (const permission of permissions) {
    uniquePermissions.add(validatePermission(permission));
  }
  const normalizedResourcePermissions = resourcePermissions.map((grant) =>
    Object.freeze({
      permission: validatePermission(grant.permission),
      context: Object.freeze({ ...grant.context }),
    }),
  );
  return Object.freeze({
    permissions: Object.freeze([...uniquePermissions]),
    resourcePermissions: Object.freeze(normalizedResourcePermissions),
  });
}

function resourceContextMatches(
  granted: PresentationResourceContext,
  requested: PresentationResourceContext,
): boolean {
  const entries = Object.entries(granted);
  if (entries.length === 0) {
    return true;
  }
  for (const [name, value] of entries) {
    if (requested[name] !== value) {
      return false;
    }
  }
  return true;
}

/**
 * Evaluates a presentation permission for UX behavior only. This never authorizes an operation.
 */
export function can(
  presentation: PresentationAuthorizationSnapshot,
  permission: PermissionId,
  resourceContext?: PresentationResourceContext,
): boolean {
  validatePermission(permission);
  if (presentation.permissions.includes(permission)) {
    return true;
  }
  if (resourceContext === undefined) {
    return false;
  }
  for (const grant of presentation.resourcePermissions) {
    if (
      grant.permission === permission &&
      resourceContextMatches(grant.context, resourceContext)
    ) {
      return true;
    }
  }
  return false;
}

/** Evaluates whether any requested UX-only presentation permission is available. */
export function canAny(
  presentation: PresentationAuthorizationSnapshot,
  permissions: readonly PermissionId[],
  resourceContext?: PresentationResourceContext,
): boolean {
  for (const permission of permissions) {
    if (can(presentation, permission, resourceContext)) {
      return true;
    }
  }
  return false;
}

/** Evaluates whether every requested UX-only presentation permission is available. */
export function canAll(
  presentation: PresentationAuthorizationSnapshot,
  permissions: readonly PermissionId[],
  resourceContext?: PresentationResourceContext,
): boolean {
  for (const permission of permissions) {
    if (!can(presentation, permission, resourceContext)) {
      return false;
    }
  }
  return true;
}

export function hasPermission(
  grantedPermissions: ReadonlySet<PermissionId>,
  permission: PermissionId,
): boolean {
  return grantedPermissions.has(permission);
}

export function satisfiesPermissionRequirement(
  grantedPermissions: ReadonlySet<PermissionId>,
  requirement: PermissionRequirement,
): boolean {
  if (requirement.allOf !== undefined) {
    for (const permission of requirement.allOf) {
      if (!grantedPermissions.has(permission)) {
        return false;
      }
    }
  }

  const anyOf = requirement.anyOf;
  if (anyOf === undefined || anyOf.length === 0) {
    return true;
  }
  for (const permission of anyOf) {
    if (grantedPermissions.has(permission)) {
      return true;
    }
  }
  return false;
}

/** Evaluates an all/any requirement against a UX-only presentation snapshot. */
export function canSatisfy(
  presentation: PresentationAuthorizationSnapshot,
  requirement: PermissionRequirement,
  resourceContext?: PresentationResourceContext,
): boolean {
  if (
    requirement.allOf !== undefined &&
    !canAll(presentation, requirement.allOf, resourceContext)
  ) {
    return false;
  }
  return requirement.anyOf === undefined ||
    requirement.anyOf.length === 0 ||
    canAny(presentation, requirement.anyOf, resourceContext);
}
