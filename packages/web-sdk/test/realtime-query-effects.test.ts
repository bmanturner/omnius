import { describe, expect, it, vi } from "vitest";

import type { DomainEventV1 } from "../src/internal/generated/realtime.js";
import {
  createRealtimeQueryEffectEngine,
  createRealtimeQueryEffectRegistry,
} from "../src/realtime/index.js";
import type {
  RealtimeQueryClient,
  RealtimeQueryKey,
} from "../src/realtime/index.js";

const EVENT_ID = "01890f47-7e7a-7c8a-9abc-1234567890ab";
const SUBSCRIPTION_ID = "01890f47-7e7a-7c8a-9abc-1234567890ac";

class QueryClientFake implements RealtimeQueryClient {
  readonly invalidated: RealtimeQueryKey[] = [];
  readonly refetched: RealtimeQueryKey[] = [];
  readonly removed: RealtimeQueryKey[] = [];
  readonly updated: RealtimeQueryKey[] = [];
  value: unknown = undefined;

  invalidateQueries(queryKey: RealtimeQueryKey): void {
    this.invalidated.push(queryKey);
  }

  refetchQueries(queryKey: RealtimeQueryKey): void {
    this.refetched.push(queryKey);
  }

  removeQueries(queryKey: RealtimeQueryKey): void {
    this.removed.push(queryKey);
  }

  setQueryData<TData>(
    queryKey: RealtimeQueryKey,
    updater: (current: TData | undefined) => TData | undefined,
  ): void {
    this.updated.push(queryKey);
    const current = this.value as TData | undefined;
    this.value = updater(current);
  }
}

function organizationEvent(organization: unknown): DomainEventV1 {
  return {
    v: 1,
    id: EVENT_ID,
    type: "organization.updated.v1",
    correlation_id: null,
    payload: {
      subscription_id: SUBSCRIPTION_ID,
      topic: "organizations/organization-1",
      cursor: "cursor-2",
      data: { organization_id: "organization-1", organization },
    },
  };
}

function createEngine(queryClient: QueryClientFake) {
  const registry = createRealtimeQueryEffectRegistry();
  const revalidateSession = vi.fn();
  const revalidateCapabilities = vi.fn();
  const diagnostics: unknown[] = [];
  const engine = createRealtimeQueryEffectEngine({
    queryClient,
    registry,
    revalidateSession,
    revalidateCapabilities,
    onDiagnostic: (diagnostic) => diagnostics.push(diagnostic),
  });
  return {
    registry,
    engine,
    revalidateSession,
    revalidateCapabilities,
    diagnostics,
  };
}

describe("realtime query effects", () => {
  it("defaults to invalidation and scopes only a supplied generated query key", async () => {
    const queryClient = new QueryClientFake();
    const { registry, engine } = createEngine(queryClient);
    const generatedKeyFactory = vi.fn((event: DomainEventV1) => [
      "generated-organizations",
      event.payload.data["organization_id"],
    ] as const);
    const unregister = registry.register("organization.updated.v1", {
      target: {
        generatedKeyFactory,
        scope: () => ({
          tenantId: "tenant-1",
          principalId: "principal-1",
          permissionScope: "permissions-v2",
        }),
      },
    });
    const event = organizationEvent({ id: "organization-1", revision: 2 });

    await engine.apply(event);

    expect(generatedKeyFactory).toHaveBeenCalledWith(event);
    expect(queryClient.invalidated).toEqual([
      [
        "omnius",
        {
          tenantId: "tenant-1",
          principalId: "principal-1",
          permissionScope: "permissions-v2",
        },
        "generated-organizations",
        "organization-1",
      ],
    ]);
    expect(queryClient.refetched).toEqual([]);
    expect(queryClient.removed).toEqual([]);

    unregister();
    await engine.apply(event);
    expect(queryClient.invalidated).toHaveLength(1);
  });

  it("patches only a validated complete representation and rejects stale revisions", async () => {
    interface Organization {
      readonly id: string;
      readonly name: string;
      readonly revision: number;
    }

    const isOrganization = (candidate: unknown): candidate is Organization => {
      if (typeof candidate !== "object" || candidate === null) {
        return false;
      }
      return (
        typeof Reflect.get(candidate, "id") === "string" &&
        typeof Reflect.get(candidate, "name") === "string" &&
        typeof Reflect.get(candidate, "revision") === "number"
      );
    };
    const queryClient = new QueryClientFake();
    const { registry, engine, diagnostics } = createEngine(queryClient);
    registry.register<"organization.updated.v1", Organization>(
      "organization.updated.v1",
      {
        type: "set-complete",
        target: {
          generatedKeyFactory: () => ["generated-organization", "organization-1"],
          scope: () => ({ tenantId: "tenant-1", principalId: "principal-1" }),
        },
        select: (event) => event.payload.data["organization"],
        validateComplete: isOrganization,
        conflictPolicy: {
          type: "newer-revision",
          revision: (organization) => organization.revision,
        },
      },
    );
    const cached = { id: "organization-1", name: "Current", revision: 3 };
    queryClient.value = cached;

    await engine.apply(
      organizationEvent({ id: "organization-1", name: "Stale", revision: 2 }),
    );
    expect(queryClient.value).toBe(cached);

    const fresh = { id: "organization-1", name: "Fresh", revision: 4 };
    await engine.apply(organizationEvent(fresh));
    expect(queryClient.value).toEqual(fresh);
    expect(diagnostics).toEqual([]);

    const setCallCount = queryClient.updated.length;
    await engine.apply(organizationEvent({ id: "organization-1", revision: 5 }));
    expect(queryClient.updated).toHaveLength(setCallCount);
    expect(queryClient.invalidated).toHaveLength(1);
    expect(diagnostics).toEqual([
      {
        code: "complete-representation-rejected",
        eventType: "organization.updated.v1",
        effect: "set-complete",
      },
    ]);
  });

  it("treats a cached null as present under the prefer-cache conflict policy", async () => {
    interface OrganizationReference {
      readonly id: string;
    }

    const isOrganizationReference = (
      candidate: unknown,
    ): candidate is OrganizationReference =>
      typeof candidate === "object" &&
      candidate !== null &&
      typeof Reflect.get(candidate, "id") === "string";
    const queryClient = new QueryClientFake();
    queryClient.value = null;
    const { registry, engine, diagnostics } = createEngine(queryClient);
    registry.register<"organization.updated.v1", OrganizationReference>(
      "organization.updated.v1",
      {
        type: "set-complete",
        target: {
          generatedKeyFactory: () => ["generated-organization", "organization-1"],
          scope: () => ({ tenantId: "tenant-1", principalId: "principal-1" }),
        },
        select: (event) => event.payload.data["organization"],
        validateComplete: isOrganizationReference,
        conflictPolicy: { type: "prefer-cache" },
      },
    );

    await engine.apply(organizationEvent({ id: "organization-1" }));

    expect(queryClient.value).toBeNull();
    expect(queryClient.updated).toHaveLength(1);
    expect(queryClient.invalidated).toEqual([]);
    expect(diagnostics).toEqual([]);
  });

  it("isolates effect and diagnostic handler exceptions while continuing later effects", async () => {
    const queryClient = new QueryClientFake();
    const registry = createRealtimeQueryEffectRegistry();
    const revalidateSession = vi.fn(() => {
      throw new Error("session endpoint failed with sensitive detail");
    });
    const revalidateCapabilities = vi.fn();
    const onDiagnostic = vi.fn(() => {
      throw new Error("diagnostic observer failed");
    });
    registry.register("organization.updated.v1", { type: "revalidate-session" });
    registry.register("organization.updated.v1", { type: "revalidate-capabilities" });
    const engine = createRealtimeQueryEffectEngine({
      queryClient,
      registry,
      revalidateSession,
      revalidateCapabilities,
      onDiagnostic,
    });

    await expect(
      engine.apply(organizationEvent({ id: "organization-1", name: "Current", revision: 1 })),
    ).resolves.toBeUndefined();
    expect(revalidateSession).toHaveBeenCalledOnce();
    expect(revalidateCapabilities).toHaveBeenCalledOnce();
    expect(onDiagnostic).toHaveBeenCalledWith({
      code: "effect-execution-failed",
      eventType: "organization.updated.v1",
      effect: "revalidate-session",
    });
  });
});
