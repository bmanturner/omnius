import { describe, expect, it } from "vitest";

import routeTopology from "../../crates/http/web-route-topology.json";
import {
  BACKEND_ROUTES,
  createDevelopmentProxy,
  createViteConfig,
  normalizeViteBasePath,
} from "../vite.config";

describe("shared backend route topology", () => {
  it("creates one proxy rule for every shared route", () => {
    const proxy = createDevelopmentProxy("http://localhost:9090");

    expect(Object.keys(proxy)).toHaveLength(routeTopology.routes.length);
    expect(BACKEND_ROUTES).toEqual(routeTopology.routes);
  });

  it("keeps service transports rooted when assets use a nested public base", () => {
    const proxy = createDevelopmentProxy("http://localhost:9090");
    const authProxy = proxy["^/auth(?:/|\\?|$)"];
    const uploadProxy = proxy["^/uploads(?:/|\\?|$)"];
    const sseProxy = proxy["^/realtime/events(?:/|\\?|$)"];
    const websocketProxy = proxy["^/realtime/ws(?:/|\\?|$)"];

    expect(authProxy).toBeDefined();
    expect(uploadProxy).toBeDefined();
    expect(sseProxy).toBeDefined();
    expect(websocketProxy?.ws).toBe(true);
    expect(proxy["^/console/auth(?:/|\\?|$)"]).toBeUndefined();
    expect(proxy["^/console/realtime/ws(?:/|\\?|$)"]).toBeUndefined();
  });

  it("configures HTTP proxy origin and forwarded-host consistency", () => {
    const proxy = createDevelopmentProxy("http://localhost:9090");

    for (const options of Object.values(proxy)) {
      expect(options).toMatchObject({
        target: "http://localhost:9090",
        changeOrigin: true,
        xfwd: true,
        timeout: 0,
        proxyTimeout: 0,
      });
    }
  });

  it("enables upgrades only for shared WebSocket routes", () => {
    const proxy = createDevelopmentProxy();

    expect(proxy["^/realtime/ws(?:/|\\?|$)"]?.ws).toBe(true);
    expect(proxy["^/ws(?:/|\\?|$)"]).toBeUndefined();
    expect(proxy["^/api(?:/|\\?|$)"]?.ws).toBe(false);
    expect(proxy["^/auth(?:/|\\?|$)"]?.ws).toBe(false);
    expect(proxy["^/tenants(?:/|\\?|$)"]?.ws).toBe(false);
    expect(proxy["^/uploads(?:/|\\?|$)"]?.ws).toBe(false);
  });

  it("keeps the SSE proxy unbounded for streaming responses", () => {
    const proxy = createDevelopmentProxy();

    expect(proxy["^/realtime/events(?:/|\\?|$)"]).toMatchObject({
      ws: false,
      timeout: 0,
      proxyTimeout: 0,
    });
  });

  it("rejects proxy targets that are not bare HTTP origins", () => {
    expect(() =>
      createDevelopmentProxy("https://user:secret@example.test/api"),
    ).toThrow("OMNIUS_DEV_PROXY_TARGET must be an HTTP origin");
  });
});

describe("production and development base paths", () => {
  it("normalizes root and explicit base paths for Vite", () => {
    expect(normalizeViteBasePath(undefined)).toBe("/");
    expect(normalizeViteBasePath("/console")).toBe("/console/");
    expect(normalizeViteBasePath("/console/")).toBe("/console/");
  });

  it("rejects traversal and encoded base paths", () => {
    expect(() => normalizeViteBasePath("/console/../admin")).toThrow(
      "OMNIUS_WEB_BASE_PATH must be a canonical absolute path",
    );
    expect(() => normalizeViteBasePath("/console%2Fadmin")).toThrow(
      "OMNIUS_WEB_BASE_PATH must be a canonical absolute path",
    );
  });

  it("uses the explicit base only for frontend development and production output", () => {
    const config = createViteConfig({
      OMNIUS_WEB_BASE_PATH: "/console",
      OMNIUS_DEV_PROXY_TARGET: "http://127.0.0.1:8080",
    });

    expect(config.base).toBe("/console/");
    expect(config.server?.proxy).toHaveProperty("^/auth(?:/|\\?|$)");
    expect(config.server?.proxy).toHaveProperty("^/uploads(?:/|\\?|$)");
    expect(config.server?.proxy).not.toHaveProperty("^/console/auth(?:/|\\?|$)");
    expect(config.preview?.proxy).toHaveProperty("^/realtime/events(?:/|\\?|$)");
    expect(config.preview?.proxy).toHaveProperty("^/realtime/ws(?:/|\\?|$)");
  });

  it("supports an explicitly consistent IPv6 development host and target", () => {
    const config = createViteConfig({
      OMNIUS_DEV_HOST: "::1",
    });

    expect(config.server?.host).toBe("::1");
    expect(config.server?.proxy).toEqual(
      createDevelopmentProxy("http://[::1]:8080"),
    );
  });
});

describe("source-map build policy", () => {
  it("disables source maps by default", () => {
    expect(createViteConfig({}).build?.sourcemap).toBe(false);
  });

  it("uses hidden maps for private error-monitoring uploads", () => {
    expect(
      createViteConfig({ OMNIUS_SOURCE_MAP_POLICY: "private" }).build?.sourcemap,
    ).toBe("hidden");
  });

  it("allows an explicit public source-map build", () => {
    expect(
      createViteConfig({ OMNIUS_SOURCE_MAP_POLICY: "public" }).build?.sourcemap,
    ).toBe(true);
  });

  it("rejects ambiguous source-map values", () => {
    expect(() =>
      createViteConfig({ OMNIUS_SOURCE_MAP_POLICY: "yes" }),
    ).toThrow(
      "OMNIUS_SOURCE_MAP_POLICY must be disabled, private, or public",
    );
  });
});

describe("release build metadata", () => {
  it("uses the same revision and build timestamp variables as Rust metadata", () => {
    const config = createViteConfig({
      OMNIUS_GIT_REVISION: "0123456789abcdef",
      OMNIUS_BUILD_TIME: "2026-08-27T18:30:00Z",
    });

    expect(config.define?.__BUILD_REVISION__).toBe(
      JSON.stringify("0123456789abcdef"),
    );
    expect(config.define?.__BUILD_TIMESTAMP__).toBe(
      JSON.stringify("2026-08-27T18:30:00Z"),
    );
  });

  it("rejects metadata values the Rust build metadata contract rejects", () => {
    expect(() =>
      createViteConfig({ OMNIUS_GIT_REVISION: "release-latest" }),
    ).toThrow("OMNIUS_GIT_REVISION must contain 7 to 64 hexadecimal characters");
    expect(() =>
      createViteConfig({ OMNIUS_BUILD_TIME: "August 27" }),
    ).toThrow("OMNIUS_BUILD_TIME must be a canonical UTC RFC 3339 timestamp");
    expect(() =>
      createViteConfig({ OMNIUS_BUILD_TIME: "2026-02-31T00:00:00Z" }),
    ).toThrow("OMNIUS_BUILD_TIME must be a canonical UTC RFC 3339 timestamp");
  });
});
