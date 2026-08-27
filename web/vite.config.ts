import { GENERATED_AGAINST_CONTRACT_HASH } from "@omnius/web-sdk/client";
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

function readBuildTimestamp(sourceDateEpoch: string | undefined): string {
  if (sourceDateEpoch === undefined) {
    return "development";
  }
  if (!/^\d+$/u.test(sourceDateEpoch)) {
    throw new Error("SOURCE_DATE_EPOCH must contain whole Unix seconds.");
  }
  return new Date(Number(sourceDateEpoch) * 1_000).toISOString();
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
  const candidate = value ?? "/";
  if (
    !candidate.startsWith("/") ||
    candidate.includes("//") ||
    /[?#%\\]/u.test(candidate)
  ) {
    throw new Error("OMNIUS_WEB_BASE_PATH must be a canonical absolute path.");
  }
  const canonical = candidate.replace(/\/+$/u, "") || "/";
  if (canonical === "/") {
    return "/";
  }
  const invalidSegment = canonical
    .split("/")
    .slice(1)
    .some(
      (segment) =>
        segment.length === 0 ||
        segment === "." ||
        segment === ".." ||
        !/^[A-Za-z0-9._~-]+$/u.test(segment),
    );
  if (invalidSegment) {
    throw new Error("OMNIUS_WEB_BASE_PATH must be a canonical absolute path.");
  }
  return `${canonical}/`;
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
    ? `^${escapedPath}$`
    : `^${escapedPath}(?:/|$)`;
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
  const buildRevision = environment.OMNIUS_BUILD_REVISION ?? "development";
  const buildTimestamp = readBuildTimestamp(environment.SOURCE_DATE_EPOCH);
  return {
    base: normalizeViteBasePath(environment.OMNIUS_WEB_BASE_PATH),
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
    build: {
      manifest: true,
      sourcemap: readSourceMapPolicy(environment.OMNIUS_SOURCE_MAP_POLICY),
      target: "es2024",
      rollupOptions: {
        output: {
          entryFileNames: "assets/[name]-[hash].js",
          chunkFileNames: "assets/[name]-[hash].js",
          assetFileNames: "assets/[name]-[hash][extname]",
        },
      },
    },
  };
}

export default defineConfig(createViteConfig());
