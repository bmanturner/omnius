import { useCallback, useState, useSyncExternalStore, type ChangeEvent } from "react";

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
}

/** Accessible tenant selection wired to the SDK's cancel-clear-reconnect-route isolation barrier. */
export function TenantSwitcher({
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
    setError(undefined);
    void coordinator.switchTenant(next).catch(() => {
      setError("The workspace could not be switched. Your previous workspace remains isolated.");
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
