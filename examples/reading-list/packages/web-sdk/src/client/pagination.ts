declare const cursorBrand: unique symbol;
export type OpaqueCursor = string & { readonly [cursorBrand]: true };

export interface CursorPagination {
  readonly cursor?: OpaqueCursor;
  readonly limit?: number;
}

export interface QueryKeyScope {
  /** Explicitly use null for data that is not tenant-scoped. */
  readonly tenantId: string | null;
  /** Explicitly use null for data that is not principal-scoped. */
  readonly principalId: string | null;
  /** Changes whenever the permission view affecting the resource changes. */
  readonly permissionScope?: string;
}

export function parseOpaqueCursor(value: string): OpaqueCursor {
  if (value.length === 0 || value.length > 256 || value.trim() !== value) {
    throw new TypeError("Cursor must be an opaque value containing 1 to 256 characters.");
  }
  return value as OpaqueCursor;
}

export function serializeCursorPagination(pagination: CursorPagination): URLSearchParams {
  const result = new URLSearchParams();
  if (pagination.cursor !== undefined) {
    result.set("cursor", parseOpaqueCursor(pagination.cursor));
  }
  if (pagination.limit !== undefined) {
    if (!Number.isSafeInteger(pagination.limit) || pagination.limit < 1 || pagination.limit > 100) {
      throw new RangeError("Cursor page limit must be an integer between 1 and 100.");
    }
    result.set("limit", String(pagination.limit));
  }
  return result;
}

export function parseCursorPagination(parameters: URLSearchParams): CursorPagination {
  const cursorValue = parameters.get("cursor");
  const limitValue = parameters.get("limit");
  let limit: number | undefined;
  if (limitValue !== null) {
    if (!/^[1-9][0-9]*$/u.test(limitValue)) {
      throw new TypeError("Cursor page limit must use canonical positive-integer syntax.");
    }
    limit = Number(limitValue);
    if (!Number.isSafeInteger(limit) || limit > 100) {
      throw new RangeError("Cursor page limit must be an integer between 1 and 100.");
    }
  }
  return {
    ...(cursorValue === null ? {} : { cursor: parseOpaqueCursor(cursorValue) }),
    ...(limit === undefined ? {} : { limit }),
  };
}

function validateScope(scope: QueryKeyScope): Readonly<QueryKeyScope> {
  for (const [name, value] of [
    ["tenantId", scope.tenantId],
    ["principalId", scope.principalId],
    ["permissionScope", scope.permissionScope],
  ] as const) {
    if (value !== undefined && value !== null && (value.length === 0 || value.trim() !== value)) {
      throw new TypeError(`${name} query-key scope must be null or a non-empty trimmed value.`);
    }
  }
  return Object.freeze({
    tenantId: scope.tenantId,
    principalId: scope.principalId,
    ...(scope.permissionScope === undefined ? {} : { permissionScope: scope.permissionScope }),
  });
}

/** Adds explicit tenant, principal, and permission isolation to a generated query key. */
export function scopeQueryKey<const TKey extends readonly unknown[]>(
  generatedKey: TKey,
  scope: QueryKeyScope,
): readonly ["omnius", Readonly<QueryKeyScope>, ...TKey] {
  return Object.freeze(["omnius", validateScope(scope), ...generatedKey]);
}
