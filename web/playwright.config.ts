import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { defineConfig, devices } from "@playwright/test";
import type { PlaywrightTestConfig } from "@playwright/test";

interface BrowserDeclaration {
  readonly project: "chromium" | "firefox" | "webkit";
  readonly engine: string;
  readonly device: "Desktop Chrome" | "Desktop Firefox" | "Desktop Safari";
  readonly supportTier: "full" | "smoke";
  readonly coverage: readonly string[];
}

interface BrowserSupport {
  readonly schemaVersion: number;
  readonly policy: string;
  readonly browsers: readonly BrowserDeclaration[];
}
type PlaywrightProject = NonNullable<PlaywrightTestConfig["projects"]>[number];

const configDirectory = fileURLToPath(new URL(".", import.meta.url));
const browserSupport = JSON.parse(
  readFileSync(new URL("./browser-support.json", import.meta.url), "utf8"),
) as BrowserSupport;
const expectedProjects = ["chromium", "firefox", "webkit"] as const;

if (
  browserSupport.schemaVersion !== 1 ||
  browserSupport.browsers.length !== expectedProjects.length ||
  expectedProjects.some(
    (name, index) => browserSupport.browsers[index]?.project !== name,
  ) ||
  browserSupport.browsers[0]?.supportTier !== "full" ||
  browserSupport.browsers.slice(1).some((browser) => browser.supportTier !== "smoke")
) {
  throw new Error("browser-support.json must declare Chromium full support and Firefox/WebKit smoke support");
}

const fixturePort = Number.parseInt(process.env.OMNIUS_E2E_PORT ?? "4174", 10);
if (!Number.isSafeInteger(fixturePort) || fixturePort < 1024 || fixturePort > 65_535) {
  throw new Error("OMNIUS_E2E_PORT must be an unprivileged TCP port");
}
const managedBaseUrl = `http://127.0.0.1:${fixturePort}`;
const baseURL = process.env.OMNIUS_E2E_BASE_URL ?? managedBaseUrl;
const usesManagedAxumFixture = process.env.OMNIUS_E2E_BASE_URL === undefined;

function projectFor(browser: BrowserDeclaration): PlaywrightProject {
  return {
    name: browser.project,
    metadata: {
      engine: browser.engine,
      supportTier: browser.supportTier,
    },
    ...(browser.supportTier === "smoke" ? { grep: /@smoke/u } : {}),
    use: {
      ...devices[browser.device],
    },
  };
}

const webServer: PlaywrightTestConfig["webServer"] = usesManagedAxumFixture
  ? {
      command: "node e2e/axum-fixture.mjs",
      cwd: configDirectory,
      env: {
        ...Object.fromEntries(
          Object.entries(process.env).filter(
            (entry): entry is [string, string] => entry[1] !== undefined,
          ),
        ),
        OMNIUS_E2E_PORT: String(fixturePort),
      },
      url: `${managedBaseUrl}/ready`,
      reuseExistingServer: process.env.CI !== "true",
      stdout: "pipe",
      stderr: "pipe",
      timeout: 120_000,
    }
  : undefined;

export default defineConfig({
  testDir: "./e2e",
  testIgnore: ["**/*.config.test.mjs"],
  outputDir: "./test-results",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI === "true" ? 1 : 0,
  forbidOnly: process.env.CI === "true",
  timeout: 30_000,
  expect: { timeout: 8_000 },
  reporter:
    process.env.CI === "true"
      ? [
          ["line"],
          ["html", { open: "never", outputFolder: "playwright-report" }],
        ]
      : [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  use: {
    baseURL,
    locale: "en-US",
    timezoneId: "UTC",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: browserSupport.browsers.map(projectFor),
  ...(webServer === undefined ? {} : { webServer }),
});
