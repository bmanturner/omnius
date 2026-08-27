import { fileURLToPath } from "node:url";
import { dirname, isAbsolute, relative, resolve } from "node:path";

import { defineConfig } from "orval";

export const WEB_SDK_ROOT = dirname(fileURLToPath(import.meta.url));
export const REPOSITORY_ROOT = resolve(WEB_SDK_ROOT, "../..");
export const CANONICAL_OPENAPI_INPUT = resolve(REPOSITORY_ROOT, "contracts/openapi.json");
export const GENERATED_HTTP_DIRECTORY = resolve(
  WEB_SDK_ROOT,
  "src/internal/generated/http",
);
export const GENERATED_HTTP_TARGET = resolve(GENERATED_HTTP_DIRECTORY, "core.ts");
export const GENERATED_QUERY_TARGET = resolve(GENERATED_HTTP_DIRECTORY, "react-query.ts");

function assertGeneratedTarget(target: string): string {
  if (/^[a-z][a-z0-9+.-]*:\/\//iu.test(target)) {
    throw new TypeError("Orval output must be a repository path, not a URL.");
  }
  const resolved = resolve(WEB_SDK_ROOT, target);
  const pathFromGeneratedRoot = relative(
    resolve(WEB_SDK_ROOT, "src/internal/generated"),
    resolved,
  );
  if (
    pathFromGeneratedRoot.length === 0 ||
    pathFromGeneratedRoot === ".." ||
    pathFromGeneratedRoot.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
    isAbsolute(pathFromGeneratedRoot)
  ) {
    throw new TypeError("Orval output must stay inside src/internal/generated.");
  }
  return resolved;
}

function commonOutput(target: string) {
  return {
    target: assertGeneratedTarget(target),
    httpClient: "fetch" as const,
    mode: "single" as const,
    clean: false,
    mock: false,
    propertySortOrder: "Alphabetical" as const,
    tsconfig: resolve(WEB_SDK_ROOT, "tsconfig.json"),
    override: {
      requestOptions: true,
      fetch: {
        includeHttpResponseReturnType: true,
      },
      mutator: {
        path: resolve(WEB_SDK_ROOT, "src/client/mutator.ts"),
        name: "serviceMutator",
        extension: ".js",
      },
    },
  };
}

/** Creates the only approved core and React Query generators for a private output directory. */
export function createTrustedOrvalConfig(targetDirectory = GENERATED_HTTP_DIRECTORY) {
  const input = {
    target: CANONICAL_OPENAPI_INPUT,
    unsafeDisableValidation: false,
    parserOptions: {
      externalRefs: {
        allow: [],
      },
    },
  };
  const core = commonOutput(resolve(targetDirectory, "core.ts"));
  const reactQuery = commonOutput(resolve(targetDirectory, "react-query.ts"));
  return defineConfig({
    serviceHttp: {
      input,
      output: {
        ...core,
        client: "fetch",
      },
    },
    serviceReactQuery: {
      input,
      output: {
        ...reactQuery,
        client: "react-query",
        override: {
          ...reactQuery.override,
          query: {
            signal: true,
            shouldExportHttpClient: false,
            shouldExportQueryKey: true,
            useOperationIdAsQueryKey: true,
            version: 5,
          },
        },
      },
    },
  });
}

export default createTrustedOrvalConfig();
