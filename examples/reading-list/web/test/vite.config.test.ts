import { describe, expect, it } from "vitest";

import { createDevelopmentProxy, createViteConfig } from "../vite.config";

describe("generated development proxy", () => {
  it("proxies auth as a prefix and whoami as an exact route", () => {
    const proxy = createDevelopmentProxy();
    const authPattern = "^/auth(?:/|\\?|$)";
    const whoamiPattern = "^/whoami(?:\\?|$)";

    expect(proxy).toHaveProperty(authPattern);
    expect(proxy).toHaveProperty(whoamiPattern);
    expect(new RegExp(authPattern, "u").test("/auth/login")).toBe(true);
    expect(new RegExp(authPattern, "u").test("/authentication")).toBe(false);
    expect(new RegExp(whoamiPattern, "u").test("/whoami?fresh=true")).toBe(true);
    expect(new RegExp(whoamiPattern, "u").test("/whoami/details")).toBe(false);
  });

  it("serves the development proxy from the configured trusted origin", () => {
    const configuration = createViteConfig({});

    expect(configuration.server).toMatchObject({
      host: "localhost",
      port: 3002,
      strictPort: true,
    });
    expect(configuration.preview).toMatchObject({
      host: "localhost",
      port: 3002,
      strictPort: true,
    });
  });
});
