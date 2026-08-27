import { describe, expect, it } from "vitest";

import {
  assertLocalStateOwnership,
  restoreLocalState,
} from "../src/react/local-state.js";
import type { StateOwnershipDescriptor } from "../src/react/local-state.js";

describe("client-local state ownership", () => {
  it("accepts declared ephemeral and versioned durable-local categories", () => {
    expect(
      assertLocalStateOwnership({
        key: "record-wizard",
        owner: "client-local",
        durability: "ephemeral",
        category: "transient-workflow",
        rationale: "Coordinates unsaved steps within the current tab.",
      }),
    ).toMatchObject({ durability: "ephemeral", category: "transient-workflow" });

    expect(
      assertLocalStateOwnership({
        key: "workspace-layout",
        owner: "client-local",
        durability: "durable-local",
        category: "panel-layout",
        rationale: "Keeps the user's device-local panel arrangement.",
        schemaVersion: 2,
      }),
    ).toMatchObject({ durability: "durable-local", schemaVersion: 2 });
  });

  it.each([
    ["remote-resource", "Remote resources"],
    ["server-resource", "Server resources"],
    ["server-truth", "server truth"],
    ["authenticated-principal", "authenticated principal"],
    ["auth-secret", "Authentication secrets"],
    ["permission-cache", "Permissions"],
  ] as const)("rejects %s ownership", (owner, expectedMessage) => {
    const descriptor: StateOwnershipDescriptor = { key: "unsafe-store", owner };
    expect(() => assertLocalStateOwnership(descriptor)).toThrow(expectedMessage);
  });
});

describe("versioned local-state restoration", () => {
  const decodeLayout = (value: unknown): { readonly panel: string } | undefined => {
    if (
      typeof value !== "object" ||
      value === null ||
      !("panel" in value) ||
      typeof value.panel !== "string"
    ) {
      return undefined;
    }
    return { panel: value.panel };
  };

  it("migrates an older schema and validates the migrated value", () => {
    const restored = restoreLocalState(
      { schemaVersion: 1, value: { selectedPanel: "activity" } },
      {
        currentSchemaVersion: 2,
        decode: decodeLayout,
        migrate: (value) => {
          if (
            typeof value !== "object" ||
            value === null ||
            !("selectedPanel" in value) ||
            typeof value.selectedPanel !== "string"
          ) {
            return undefined;
          }
          return { panel: value.selectedPanel };
        },
      },
    );

    expect(restored).toEqual({
      status: "migrated",
      schemaVersion: 2,
      previousSchemaVersion: 1,
      value: { panel: "activity" },
    });
  });

  it("discards stale, future, malformed, and invalid state safely", () => {
    expect(
      restoreLocalState(
        { schemaVersion: 1, value: { panel: "activity" } },
        { currentSchemaVersion: 2, decode: decodeLayout },
      ),
    ).toEqual({ status: "discarded", reason: "migration-unavailable" });

    expect(
      restoreLocalState(
        { schemaVersion: 3, value: { panel: "activity" } },
        { currentSchemaVersion: 2, decode: decodeLayout },
      ),
    ).toEqual({ status: "discarded", reason: "future-version" });

    expect(
      restoreLocalState({ value: { panel: "activity" } }, {
        currentSchemaVersion: 2,
        decode: decodeLayout,
      }),
    ).toEqual({ status: "discarded", reason: "malformed-envelope" });

    expect(
      restoreLocalState(
        { schemaVersion: 2, value: { panel: 42 } },
        { currentSchemaVersion: 2, decode: decodeLayout },
      ),
    ).toEqual({ status: "discarded", reason: "invalid-current-value" });

    const hostileEnvelope = new Proxy(
      {},
      {
        getOwnPropertyDescriptor: () => {
          throw new Error("hostile local-state property");
        },
      },
    );
    expect(
      restoreLocalState(hostileEnvelope, {
        currentSchemaVersion: 2,
        decode: decodeLayout,
      }),
    ).toEqual({ status: "discarded", reason: "malformed-envelope" });
  });
});
