import { scopeQueryKey } from "../client/index.js";
import type { QueryKeyScope } from "../client/index.js";

/** Uses the scoped-key contract for every tenant-aware generated query key. */
export function scopeTenantQueryKey<const TKey extends readonly unknown[]>(
  generatedKey: TKey,
  scope: QueryKeyScope,
): readonly ["omnius", Readonly<QueryKeyScope>, ...TKey] {
  return scopeQueryKey(generatedKey, scope);
}
