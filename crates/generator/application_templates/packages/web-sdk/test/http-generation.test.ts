import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";

import { describe, expect, it } from "vitest";

import {
  CANONICAL_OPENAPI_INPUT,
  REPOSITORY_ROOT,
  createTrustedOrvalConfig,
} from "../orval.config.js";
import {
  assertCanonicalOpenApiInput,
  findStaleGeneratedFiles,
  validateCanonicalOpenApiDocument,
} from "../scripts/http-generation.js";

function minimalDocument(): Record<string, unknown> {
  return {
    openapi: "3.1.0",
    info: { title: "test", version: "1" },
    components: { schemas: { Result: { type: "object" } } },
    paths: {
      "/result": {
        get: {
          operationId: "getResult",
          responses: {
            "200": {
              description: "ok",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/Result" },
                },
              },
            },
          },
        },
      },
    },
  };
}

describe("trusted HTTP generation boundary", () => {
  it("accepts an application contract with no operations", () => {
    expect(() =>
      validateCanonicalOpenApiDocument({
        openapi: "3.1.0",
        info: { title: "empty application", version: "0.1.0" },
        components: { schemas: {} },
        paths: {},
      }),
    ).not.toThrow();
  });

  it("retains both trusted generators for future application operations", () => {
    const configuration = createTrustedOrvalConfig();
    expect(Object.keys(configuration)).toEqual(["serviceHttp", "serviceReactQuery"]);
  });

  it("accepts only the canonical repository OpenAPI path", async () => {
    await expect(
      assertCanonicalOpenApiInput(
        CANONICAL_OPENAPI_INPUT,
        REPOSITORY_ROOT,
        CANONICAL_OPENAPI_INPUT,
      ),
    ).resolves.toBe(CANONICAL_OPENAPI_INPUT);
    await expect(
      assertCanonicalOpenApiInput(
        new URL("https://example.test/openapi.json"),
        REPOSITORY_ROOT,
        CANONICAL_OPENAPI_INPUT,
      ),
    ).rejects.toThrow(/URL inputs/u);
    await expect(
      assertCanonicalOpenApiInput(
        dirname(REPOSITORY_ROOT),
        REPOSITORY_ROOT,
        CANONICAL_OPENAPI_INPUT,
      ),
    ).rejects.toThrow(/outside/u);
  });

  it("rejects unresolved, external, and unsupported contract shapes", () => {
    const external = minimalDocument();
    const externalPaths = external.paths as Record<string, Record<string, unknown>>;
    const resultPath = externalPaths["/result"];
    if (resultPath === undefined) {
      throw new Error("Test OpenAPI path is missing.");
    }
    resultPath.get = {
      operationId: "getResult",
      responses: { "200": { $ref: "https://example.test/response.json" } },
    };
    expect(() => validateCanonicalOpenApiDocument(external)).toThrow(/external/u);

    const unresolved = minimalDocument();
    const unresolvedPaths = unresolved.paths as Record<string, Record<string, unknown>>;
    const unresolvedPath = unresolvedPaths["/result"];
    if (unresolvedPath === undefined) {
      throw new Error("Test OpenAPI path is missing.");
    }
    unresolvedPath.get = {
      operationId: "getResult",
      responses: { "200": { $ref: "#/components/schemas/Missing" } },
    };
    expect(() => validateCanonicalOpenApiDocument(unresolved)).toThrow(/unresolved/u);
    expect(() =>
      validateCanonicalOpenApiDocument({
        ...minimalDocument(),
        openapi: "2.0",
      }),
    ).toThrow(/OpenAPI 3\.1/u);
  });

  it("detects byte-level stale output while identical output remains deterministic", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnius-http-generation-"));
    const expected = join(root, "expected");
    const generated = join(root, "generated");
    try {
      await mkdir(expected);
      await mkdir(generated);
      await writeFile(join(expected, "client.ts"), "export const value = 1;\n", "utf8");
      await writeFile(join(generated, "client.ts"), "export const value = 1;\n", "utf8");
      await expect(findStaleGeneratedFiles(expected, generated)).resolves.toEqual([]);

      await writeFile(join(generated, "client.ts"), "export const value = 2;\n", "utf8");
      await expect(findStaleGeneratedFiles(expected, generated)).resolves.toEqual(["client.ts"]);
      await writeFile(join(generated, "extra.ts"), "export {};\n", "utf8");
      await expect(findStaleGeneratedFiles(expected, generated)).resolves.toEqual([
        "client.ts",
        "extra.ts",
      ]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
