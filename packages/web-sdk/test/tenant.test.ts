import { QueryClient } from "@tanstack/react-query";
import { describe, expect, it, vi } from "vitest";

import {
  createQueryIdentityTransitionLifecycle,
  createTenantTransitionCoordinator,
  scopeTenantQueryKey,
} from "../src/react/index.js";
import { createDeferred } from "../src/testing/index.js";

describe("tenant query isolation", () => {
  it("scopes keys and hides old data before cancel/remove/reset/realtime/route ordering", async () => {
    const queryClient = new QueryClient();
    const oldScope = {
      tenantId: "tenant-old",
      principalId: "principal-1",
      permissionScope: "permissions-1",
    } as const;
    const nextScope = {
      tenantId: "tenant-new",
      principalId: "principal-1",
      permissionScope: "permissions-1",
    } as const;
    const oldKey = scopeTenantQueryKey(["records"] as const, oldScope);
    const nextKey = scopeTenantQueryKey(["records"] as const, nextScope);
    queryClient.setQueryData(oldKey, ["old-tenant-record"]);
    queryClient.setQueryData(nextKey, ["new-tenant-record"]);

    const order: string[] = [];
    const cancellation = createDeferred<void>();
    vi.spyOn(queryClient, "cancelQueries").mockImplementation(async () => {
      order.push("cancel");
      await cancellation.promise;
    });
    const coordinator = createTenantTransitionCoordinator({
      queryClient,
      initialScope: oldScope,
      localState: [
        {
          resetForTenantTransition(): void {
            order.push("local");
          },
        },
      ],
      realtime: {
        reestablishForTenant(): void {
          order.push("realtime");
        },
      },
      route: {
        replaceTenantRoute(): void {
          order.push("route");
        },
      },
    });

    const transition = coordinator.switchTenant(nextScope);
    expect(coordinator.getSnapshot()).toEqual({
      status: "transitioning",
      previous: oldScope,
      next: nextScope,
    });
    expect(queryClient.getQueryData(oldKey)).toEqual(["old-tenant-record"]);
    expect(order).toEqual(["cancel"]);

    cancellation.resolve();
    await transition;
    expect(order).toEqual(["cancel", "local", "realtime", "route"]);
    expect(queryClient.getQueryData(oldKey)).toBeUndefined();
    expect(queryClient.getQueryData(nextKey)).toEqual(["new-tenant-record"]);
    expect(coordinator.getSnapshot()).toEqual({ status: "ready", scope: nextScope });
  });

  it("cancels before removing all prior principal/tenant scoped queries on identity change", async () => {
    const queryClient = new QueryClient();
    const principalKey = scopeTenantQueryKey(["profile"] as const, {
      tenantId: null,
      principalId: "principal-old",
    });
    const tenantKey = scopeTenantQueryKey(["records"] as const, {
      tenantId: "tenant-old",
      principalId: "principal-old",
    });
    const publicKey = scopeTenantQueryKey(["runtime"] as const, {
      tenantId: null,
      principalId: null,
    });
    queryClient.setQueryData(principalKey, { private: true });
    queryClient.setQueryData(tenantKey, { private: true });
    queryClient.setQueryData(publicKey, { public: true });
    const order: string[] = [];
    const originalCancel = queryClient.cancelQueries.bind(queryClient);
    vi.spyOn(queryClient, "cancelQueries").mockImplementation(async (filters) => {
      order.push("cancel");
      await originalCancel(filters);
    });
    const originalRemove = queryClient.removeQueries.bind(queryClient);
    vi.spyOn(queryClient, "removeQueries").mockImplementation((filters) => {
      order.push("remove");
      originalRemove(filters);
    });
    const identityLifecycle = createQueryIdentityTransitionLifecycle({
      queryClient,
      localState: [
        {
          resetForIdentityTransition(): void {
            order.push("local");
          },
        },
      ],
      realtime: {
        resetForIdentityTransition(): void {
          order.push("realtime");
        },
      },
    });

    await identityLifecycle.transition({
      reason: "principal-change",
      previous: {
        status: "authenticated",
        mode: "session",
        principal: { subject: "principal-old", kind: "user" },
        session: {
          authenticatedAt: "2026-08-27T10:00:00Z",
          authenticationMethod: "password",
          assurance: "aal1",
        },
        presentation: { permissions: ["records.read"], resourcePermissions: [] },
        scopes: ["openid"],
        tenant: { id: "tenant-old" },
      },
      next: {
        status: "authenticated",
        mode: "session",
        principal: { subject: "principal-new", kind: "user" },
        session: {
          authenticatedAt: "2026-08-27T11:00:00Z",
          authenticationMethod: "password",
          assurance: "aal1",
        },
        presentation: { permissions: ["records.read"], resourcePermissions: [] },
        scopes: ["openid"],
        tenant: { id: "tenant-new" },
      },
    });

    expect(order).toEqual(["cancel", "remove", "local", "realtime"]);
    expect(queryClient.getQueryData(principalKey)).toBeUndefined();
    expect(queryClient.getQueryData(tenantKey)).toBeUndefined();
    expect(queryClient.getQueryData(publicKey)).toEqual({ public: true });
  });
});
