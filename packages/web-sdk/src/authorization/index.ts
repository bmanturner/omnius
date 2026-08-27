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
