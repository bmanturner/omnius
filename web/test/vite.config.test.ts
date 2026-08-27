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

    expect(proxy["^/realtime/ws(?:/|$)"]?.ws).toBe(true);
    expect(proxy["^/ws(?:/|$)"]?.ws).toBe(true);
    expect(proxy["^/api(?:/|$)"]?.ws).toBe(false);
  });

  it("keeps the SSE proxy unbounded for streaming responses", () => {
    const proxy = createDevelopmentProxy();

    expect(proxy["^/events(?:/|$)"]).toMatchObject({
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

  it("uses the same explicit base for development and production output", () => {
    const config = createViteConfig({
      OMNIUS_WEB_BASE_PATH: "/console",
      OMNIUS_DEV_PROXY_TARGET: "http://127.0.0.1:8080",
    });

    expect(config.base).toBe("/console/");
    expect(config.server?.proxy).toBeDefined();
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
