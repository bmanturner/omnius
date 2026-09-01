import {
  useCallback,
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
  type ChangeEvent,
} from "react";

import type { QueryKeyScope } from "@omnius/web-sdk/client";
import type { TenantTransitionCoordinator } from "@omnius/web-sdk/react";

export interface TenantSwitchOption {
  readonly tenantId: string;
  readonly name: string;
  /** Monotonic membership/grant version used to isolate permission-sensitive query keys. */
  readonly permissionScope: string;
}

export interface TenantSwitcherProps {
  readonly coordinator: TenantTransitionCoordinator;
  readonly principalId: string;
  readonly tenants: readonly TenantSwitchOption[];
  readonly label?: string;
  readonly activateTenant: (
    tenant: Readonly<TenantSwitchOption>,
    signal: AbortSignal,
  ) => Promise<void>;
}

/** Accessible tenant selection wired to the SDK's cancel-clear-reconnect-route isolation barrier. */
export function TenantSwitcher({
  activateTenant,
  coordinator,
  principalId,
  tenants,
  label = "Active workspace",
}: TenantSwitcherProps) {
  const subscribe = useCallback(
    (listener: () => void) => coordinator.subscribe(() => listener()),
    [coordinator],
  );
  const snapshot = useSyncExternalStore(subscribe, coordinator.getSnapshot, coordinator.getSnapshot);
  const activeAbort = useRef<AbortController | undefined>(undefined);
  useEffect(
    () => () => {
      activeAbort.current?.abort();
    },
    [],
  );
  const [error, setError] = useState<string>();
  const activeTenantId = snapshot.status === "ready" ? snapshot.scope.tenantId ?? "" : snapshot.next.tenantId ?? "";

  const switchTenant = (event: ChangeEvent<HTMLSelectElement>): void => {
    const selected = tenants.find((tenant) => tenant.tenantId === event.target.value);
    if (selected === undefined || snapshot.status !== "ready") return;
    const next: QueryKeyScope = Object.freeze({
      tenantId: selected.tenantId,
      principalId,
      permissionScope: selected.permissionScope,
    });
    activeAbort.current?.abort();
    const abort = new AbortController();
    activeAbort.current = abort;
    setError(undefined);
    void activateTenant(selected, abort.signal)
      .then(async () => coordinator.switchTenant(next, { signal: abort.signal }))
      .catch(() => {
        if (!abort.signal.aborted) {
          setError("The workspace could not be switched. Your previous workspace remains isolated.");
        }
      })
      .finally(() => {
        if (activeAbort.current === abort) activeAbort.current = undefined;
      });
  };

  return (
    <div className="tenant-switcher">
      <label>
        <span>{label}</span>
        <select
          aria-describedby={error === undefined ? undefined : "tenant-switch-error"}
          disabled={snapshot.status === "transitioning" || tenants.length === 0}
          onChange={switchTenant}
          value={activeTenantId}
        >
          {tenants.map((tenant) => (
            <option key={tenant.tenantId} value={tenant.tenantId}>
              {tenant.name}
            </option>
          ))}
        </select>
      </label>
      <p aria-live="polite" role="status">
        {snapshot.status === "transitioning" ? "Switching workspace and clearing prior tenant data…" : ""}
      </p>
      {error === undefined ? null : (
        <p id="tenant-switch-error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
