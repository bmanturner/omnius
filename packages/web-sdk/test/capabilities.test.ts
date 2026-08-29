import { describe, expect, it } from "vitest";

import {
  CapabilityContractError,
  createCapabilityRegistry,
  parseCapabilityManifest,
  requireCompiledCapability,
  requireEntitlement,
  requirePermission,
  requireProductFlag,
  requireRuntimeCapability,
  resolveEntitlement,
  resolvePermission,
  resolveProductFlag,
} from "../src/capabilities/index.js";

const canonicalManifest = {
  schema_version: "1.0.0",
  service_version: "0.1.0",
  profile: "test",
  contract_hash: `sha256:${"a".repeat(64)}`,
  capabilities: [
    {
      id: "compiled-offline",
      compiled: true,
      runtime_available: false,
      minimum_sdk_version: "0.1.0",
      auth_modes: ["bearer"],
      auth_roles: [
        "oauth-authorization-server",
        "oauth-resource-server",
        "openid-provider",
      ],
    },
    {
      id: "not-compiled",
      compiled: false,
      runtime_available: false,
      minimum_sdk_version: "0.1.0",
      auth_modes: ["session"],
    },
  ],
  transports: { api: "/api", sse: "/events", websocket: "/realtime/ws" },
};

describe("capability registry", () => {
  it("strictly parses canonical metadata and freezes the normalized shape", () => {
    const parsed = parseCapabilityManifest(canonicalManifest);
    expect(parsed.schemaVersion).toBe("1.0.0");
    expect(parsed.capabilities[0]).toEqual({
      id: "compiled-offline",
      compiled: true,
      runtimeAvailable: false,
      minimumSdkVersion: "0.1.0",
      authModes: ["bearer"],
      authRoles: [
        "oauth-authorization-server",
        "oauth-resource-server",
        "openid-provider",
      ],
    });
    expect(Object.isFrozen(parsed.capabilities)).toBe(true);
    expect(() =>
      parseCapabilityManifest({
        ...canonicalManifest,
        capabilities: [canonicalManifest.capabilities[0], canonicalManifest.capabilities[0]],
      }),
    ).toThrow(CapabilityContractError);
  });

  it("accepts profiles that omit unselected realtime transports", () => {
    const parsed = parseCapabilityManifest({
      ...canonicalManifest,
      transports: { api: "/api" },
    });

    expect(parsed.transports).toEqual({ api: "/api" });
    expect(() =>
      parseCapabilityManifest({
        ...canonicalManifest,
        transports: { api: "/api", sse: "" },
      }),
    ).toThrow(CapabilityContractError);
  });

  it("defaults authentication roles for capability documents from before role metadata", () => {
    const parsed = parseCapabilityManifest({
      ...canonicalManifest,
      capabilities: [canonicalManifest.capabilities[1]],
    });

    expect(parsed.capabilities[0]?.authRoles).toEqual([]);
  });

  it("rejects unknown or duplicate roles without accepting protocol roles as credential modes", () => {
    for (const authRoles of [
      ["oauth-client"],
      ["oauth-resource-server", "oauth-resource-server"],
    ]) {
      expect(() =>
        parseCapabilityManifest({
          ...canonicalManifest,
          capabilities: [{ ...canonicalManifest.capabilities[0], auth_roles: authRoles }],
        }),
      ).toThrow(CapabilityContractError);
    }

    expect(() =>
      parseCapabilityManifest({
        ...canonicalManifest,
        capabilities: [
          {
            ...canonicalManifest.capabilities[0],
            auth_modes: ["oauth-resource-server"],
          },
        ],
      }),
    ).toThrow(CapabilityContractError);
  });

  it("never promotes an uncompiled capability from injected runtime metadata", () => {
    const registry = createCapabilityRegistry(canonicalManifest, {
      capabilities: ["compiled-offline", "not-compiled"],
    });
    expect(registry.resolveCompiled("compiled-offline")).toMatchObject({
      dimension: "compiled-capability",
      compiled: true,
    });
    expect(registry.resolveRuntimeAvailability("compiled-offline")).toEqual({
      dimension: "runtime-availability",
      capabilityId: "compiled-offline",
      availability: "available",
      available: true,
    });
    expect(registry.resolveRuntimeAvailability("not-compiled")).toEqual({
      dimension: "runtime-availability",
      capabilityId: "not-compiled",
      availability: "not-compiled",
      available: false,
    });
  });

  it("publishes cached runtime snapshots only when metadata changes", () => {
    const registry = createCapabilityRegistry(canonicalManifest);
    const initial = registry.resolveRuntimeAvailability("compiled-offline");
    let notifications = 0;
    const unsubscribe = registry.subscribe(() => {
      notifications += 1;
    });
    registry.updateRuntimeMetadata({ capabilities: { "compiled-offline": false } });
    expect(registry.resolveRuntimeAvailability("compiled-offline")).toBe(initial);
    expect(notifications).toBe(0);
    registry.updateRuntimeMetadata({ capabilities: { "compiled-offline": true } });
    expect(registry.resolveRuntimeAvailability("compiled-offline")).not.toBe(initial);
    expect(notifications).toBe(1);
    unsubscribe();
  });

  it("keeps compiled, runtime, flag, entitlement, and permission decisions non-interchangeable", async () => {
    const registry = createCapabilityRegistry(canonicalManifest, {
      capabilities: ["compiled-offline"],
    });
    const compiled = registry.resolveCompiled("compiled-offline");
    const runtime = registry.resolveRuntimeAvailability("compiled-offline");
    const flag = await resolveProductFlag(
      { evaluateProductFlag: () => false },
      "new-editor",
      undefined,
    );
    const entitlement = await resolveEntitlement(
      { evaluateEntitlement: () => true },
      "storage-pro",
      undefined,
    );
    const permission = await resolvePermission(
      { evaluatePermission: () => false },
      "uploads.write",
      undefined,
    );

    expect(compiled.dimension).toBe("compiled-capability");
    expect(runtime.dimension).toBe("runtime-availability");
    expect(flag).toEqual({ dimension: "product-flag", flagId: "new-editor", enabled: false });
    expect(entitlement).toEqual({
      dimension: "entitlement",
      entitlementId: "storage-pro",
      entitled: true,
    });
    expect(permission).toEqual({
      dimension: "permission",
      permissionId: "uploads.write",
      permitted: false,
    });

    expect(() => requireCompiledCapability(compiled)).not.toThrow();
    expect(() => requireRuntimeCapability(runtime)).not.toThrow();
    expect(() => requireProductFlag(flag)).toThrow("disabled");
    expect(() => requireEntitlement(entitlement)).not.toThrow();
    expect(() => requirePermission(permission)).toThrow("denied");

    if (false) {
      // @ts-expect-error Structural composition is not runtime availability.
      requireRuntimeCapability(compiled);
      // @ts-expect-error A product flag cannot satisfy an entitlement.
      requireEntitlement(flag);
      // @ts-expect-error An entitlement cannot satisfy a permission.
      requirePermission(entitlement);
    }
  });
});
