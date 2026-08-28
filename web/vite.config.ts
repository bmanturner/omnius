import {
  GENERATED_AGAINST_CONTRACT_HASH,
  normalizePublicBasePath,
} from "@omnius/web-sdk/client";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import type { Plugin, ProxyOptions, UserConfig } from "vite";

import routeTopology from "../crates/http/web-route-topology.json" with { type: "json" };

const DEFAULT_PROXY_TARGET = "http://127.0.0.1:8080";

type BackendRouteDefinition = Readonly<{
  path: string;
  match: "exact" | "prefix";
  transport: "http" | "websocket" | "sse";
}>;

function readBackendRoutes(): readonly BackendRouteDefinition[] {
  if (routeTopology.version !== 1 || routeTopology.routes.length === 0) {
    throw new Error("Unsupported or empty backend route topology.");
  }
  const identities = new Set<string>();
  for (const route of routeTopology.routes) {
    const identity = `${route.match}:${route.path}`;
    if (
      !/^\/(?:[^/?#%]+(?:\/[^/?#%]+)*)$/u.test(route.path) ||
      !["exact", "prefix"].includes(route.match) ||
      !["http", "websocket", "sse"].includes(route.transport) ||
      identities.has(identity)
    ) {
      throw new Error("Invalid backend route topology.");
    }
    identities.add(identity);
  }
  return routeTopology.routes as readonly BackendRouteDefinition[];
}

export const BACKEND_ROUTES = readBackendRoutes();

function readBuildTimestamp(value: string | undefined): string {
  if (value === undefined) {
    return "development";
  }
  const parsed = new Date(value);
  const canonical = value.includes(".")
    ? value
    : `${value.slice(0, -1)}.000Z`;
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value) ||
    Number.isNaN(parsed.valueOf()) ||
    parsed.toISOString() !== canonical
  ) {
    throw new Error("OMNIUS_BUILD_TIME must be a canonical UTC RFC 3339 timestamp.");
  }
  return value;
}

function readBuildRevision(value: string | undefined): string {
  if (value === undefined) {
    return "development";
  }
  if (!/^[a-fA-F0-9]{7,64}$/u.test(value)) {
    throw new Error("OMNIUS_GIT_REVISION must contain 7 to 64 hexadecimal characters.");
  }
  return value;
}

function readSourceMapPolicy(
  value: string | undefined,
): boolean | "hidden" {
  if (value === undefined || value === "disabled") {
    return false;
  }
  if (value === "private") {
    return "hidden";
  }
  if (value === "public") {
    return true;
  }
  throw new Error(
    "OMNIUS_SOURCE_MAP_POLICY must be disabled, private, or public.",
  );
}

function contractMetadataPlugin(): Plugin {
  return {
    name: "omnius-contract-metadata",
    transformIndexHtml(html) {
      return html.replaceAll(
        "__OMNIUS_CONTRACT_HASH_META__",
        GENERATED_AGAINST_CONTRACT_HASH,
      );
    },
  };
}

export function normalizeViteBasePath(value: string | undefined): string {
  try {
    const publicBasePath = normalizePublicBasePath(value);
    return publicBasePath === "/" ? "/" : `${publicBasePath}/`;
  } catch (cause: unknown) {
    throw new Error("OMNIUS_WEB_BASE_PATH must be a canonical absolute path.", { cause });
  }
}

function normalizeProxyTarget(value: string | undefined): string {
  let target: URL;
  try {
    target = new URL(value ?? DEFAULT_PROXY_TARGET);
  } catch {
    throw new Error("OMNIUS_DEV_PROXY_TARGET must be an HTTP origin.");
  }
  if (
    !["http:", "https:"].includes(target.protocol) ||
    target.username !== "" ||
    target.password !== "" ||
    target.pathname !== "/" ||
    target.search !== "" ||
    target.hash !== ""
  ) {
    throw new Error("OMNIUS_DEV_PROXY_TARGET must be an HTTP origin.");
  }
  return target.origin;
}

function proxyPattern(route: BackendRouteDefinition): string {
  const escapedPath = route.path.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return route.match === "exact"
    ? `^${escapedPath}(?:\\?|$)`
    : `^${escapedPath}(?:/|\\?|$)`;
}

export function createDevelopmentProxy(
  targetValue?: string,
): Record<string, ProxyOptions> {
  const target = normalizeProxyTarget(targetValue);
  return Object.fromEntries(
    BACKEND_ROUTES.map((route) => [
      proxyPattern(route),
      {
        target,
        changeOrigin: true,
        xfwd: true,
        ws: route.transport === "websocket",
        timeout: 0,
        proxyTimeout: 0,
      },
    ]),
  );
}

export function createViteConfig(
  environment: NodeJS.ProcessEnv = process.env,
): UserConfig {
  const developmentHost = environment.OMNIUS_DEV_HOST ?? "127.0.0.1";
  const proxyTarget =
    environment.OMNIUS_DEV_PROXY_TARGET ??
    (developmentHost === "::1"
      ? "http://[::1]:8080"
      : developmentHost === "localhost"
        ? "http://localhost:8080"
        : DEFAULT_PROXY_TARGET);
  const buildRevision = readBuildRevision(environment.OMNIUS_GIT_REVISION);
  const buildTimestamp = readBuildTimestamp(environment.OMNIUS_BUILD_TIME);
  const publicBasePath = normalizePublicBasePath(
    environment.OMNIUS_WEB_BASE_PATH,
  );
  return {
    base: publicBasePath === "/" ? "/" : `${publicBasePath}/`,
    plugins: [contractMetadataPlugin(), react()],
    define: {
      __BUILD_REVISION__: JSON.stringify(buildRevision),
      __BUILD_TIMESTAMP__: JSON.stringify(buildTimestamp),
    },
    server: {
      host: developmentHost,
      strictPort: true,
      proxy: createDevelopmentProxy(proxyTarget),
    },
    preview: {
      host: developmentHost,
      strictPort: true,
      proxy: createDevelopmentProxy(proxyTarget),
    },
    build: {
      manifest: true,
      sourcemap: readSourceMapPolicy(environment.OMNIUS_SOURCE_MAP_POLICY),
      target: "es2024",
      rollupOptions: {
        output: {
          entryFileNames: "assets/[name]-[hash].js",
          chunkFileNames: "assets/[name]-[hash].js",
          assetFileNames: "assets/[name]-[hash][extname]",
          manualChunks(moduleId) {
            const normalized = moduleId.replaceAll("\\", "/");
            if (
              normalized.includes("/packages/web-sdk/dist/realtime/") ||
              normalized.includes("/packages/web-sdk/dist/react/realtime.") ||
              normalized.includes("/packages/web-sdk/dist/uploads/")
            ) {
              return "web-sdk-streaming";
            }
          },
        },
      },
    },
  };
}

export default defineConfig(createViteConfig());
