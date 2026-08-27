import { readFile, stat, writeFile } from "node:fs/promises";

import { expect, test } from "./fixtures";

interface PerformanceBudget {
  readonly schemaVersion: number;
  readonly bundle: {
    readonly entryJavaScriptBytes: number;
    readonly routeChunkBytes: number;
    readonly totalJavaScriptBytes: number;
    readonly totalCssBytes: number;
  };
  readonly runtime: {
    readonly startupRequests: number;
    readonly applicationShellRenderMs: number;
    readonly routeTransitionMs: number;
    readonly apiWaterfallDepth: number;
    readonly longTasks: {
      readonly count: number;
      readonly maxDurationMs: number;
    };
  };
}

interface ViteManifestEntry {
  readonly file: string;
  readonly css?: readonly string[];
  readonly isEntry?: boolean;
  readonly isDynamicEntry?: boolean;
}

interface BundleMeasurements {
  readonly entryJavaScriptBytes: number;
  readonly largestRouteChunkBytes: number;
  readonly totalJavaScriptBytes: number;
  readonly totalCssBytes: number;
}

interface RuntimeMeasurements {
  readonly startupRequests: number;
  readonly applicationShellRenderMs: number;
  readonly routeTransitionMs: number;
  readonly apiWaterfallDepth: number;
  readonly longTaskCount: number;
  readonly longestTaskMs: number;
}

const budget = JSON.parse(
  await readFile(new URL("./performance-budget.json", import.meta.url), "utf8"),
) as PerformanceBudget;
const distDirectory = new URL("../dist/", import.meta.url);

async function sizeOf(relativePath: string): Promise<number> {
  return (await stat(new URL(relativePath, distDirectory))).size;
}

async function measureBundles(): Promise<BundleMeasurements> {
  const manifest = JSON.parse(
    await readFile(new URL(".vite/manifest.json", distDirectory), "utf8"),
  ) as Readonly<Record<string, ViteManifestEntry>>;
  const entries = Object.values(manifest);
  const javascriptFiles = [...new Set(entries.map((entry) => entry.file).filter((file) => file.endsWith(".js")))];
  const cssFiles = [
    ...new Set(entries.flatMap((entry) => entry.css ?? []).filter((file) => file.endsWith(".css"))),
  ];
  const entryFiles = entries.filter((entry) => entry.isEntry === true).map((entry) => entry.file);
  const routeFiles = entries
    .filter((entry) => entry.isDynamicEntry === true)
    .map((entry) => entry.file);
  const [javascriptSizes, cssSizes, entrySizes, routeSizes] = await Promise.all([
    Promise.all(javascriptFiles.map(sizeOf)),
    Promise.all(cssFiles.map(sizeOf)),
    Promise.all(entryFiles.map(sizeOf)),
    Promise.all(routeFiles.map(sizeOf)),
  ]);
  return {
    entryJavaScriptBytes: entrySizes.reduce((total, size) => total + size, 0),
    largestRouteChunkBytes: Math.max(0, ...routeSizes),
    totalJavaScriptBytes: javascriptSizes.reduce((total, size) => total + size, 0),
    totalCssBytes: cssSizes.reduce((total, size) => total + size, 0),
  };
}

function apiWaterfallDepth(entries: readonly PerformanceResourceTiming[]): number {
  const layers: { readonly entry: PerformanceResourceTiming; readonly depth: number }[] = [];
  for (const entry of [...entries].sort((left, right) => left.startTime - right.startTime)) {
    const priorDepth = layers
      .filter((layer) => layer.entry.responseEnd <= entry.startTime)
      .reduce((depth, layer) => Math.max(depth, layer.depth), 0);
    layers.push({ entry, depth: priorDepth + 1 });
  }
  return layers.reduce((depth, layer) => Math.max(depth, layer.depth), 0);
}

test("production bundle sizes stay within the configured regression budget", async ({}, testInfo) => {
  expect(budget.schemaVersion).toBe(1);
  const measurements = await measureBundles();
  expect(measurements.entryJavaScriptBytes).toBeLessThanOrEqual(
    budget.bundle.entryJavaScriptBytes,
  );
  expect(measurements.largestRouteChunkBytes).toBeLessThanOrEqual(budget.bundle.routeChunkBytes);
  expect(measurements.totalJavaScriptBytes).toBeLessThanOrEqual(
    budget.bundle.totalJavaScriptBytes,
  );
  expect(measurements.totalCssBytes).toBeLessThanOrEqual(budget.bundle.totalCssBytes);
  await writeFile(
    testInfo.outputPath("bundle-measurements.json"),
    `${JSON.stringify({ budget: budget.bundle, measured: measurements }, null, 2)}\n`,
  );
});

test("actual-Axum shell and route runtime stay within the configured budget", async ({ page }, testInfo) => {
  await page.addInitScript(() => {
    const global = globalThis as typeof globalThis & { __omniusLongTasks?: number[] };
    global.__omniusLongTasks = [];
    if (typeof PerformanceObserver === "function") {
      const observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          global.__omniusLongTasks?.push(entry.duration);
        }
      });
      observer.observe({ type: "longtask", buffered: true });
    }
  });

  const startupUrls: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin === new URL(testInfo.project.use.baseURL ?? "http://127.0.0.1").origin) {
      startupUrls.push(url.href);
    }
  });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Service overview", level: 1 })).toBeVisible();
  await expect(page.getByText("ready", { exact: true }).first()).toBeVisible();
  const startupRequests = startupUrls.length;
  const applicationShellRenderMs = await page.evaluate(() => performance.now());
  const resourceTimings = await page.evaluate(() =>
    (performance.getEntriesByType("resource") as PerformanceResourceTiming[]).map((entry) => ({
      name: entry.name,
      responseEnd: entry.responseEnd,
      startTime: entry.startTime,
    })),
  );
  const apiTimings = resourceTimings
    .filter((entry) => {
      const pathname = new URL(entry.name).pathname;
      return pathname === "/ready" || pathname === "/api/_meta";
    })
    .map(
      (entry) =>
        ({
          ...entry,
        }) as PerformanceResourceTiming,
    );

  const transitionStart = await page.evaluate(() => performance.now());
  await page.getByRole("link", { name: "Reference records" }).click();
  await expect(page.getByRole("heading", { name: "Reference records", level: 1 })).toBeVisible();
  const routeTransitionMs = await page.evaluate(
    (start) => performance.now() - start,
    transitionStart,
  );
  await page.waitForTimeout(0);
  const longTasks = await page.evaluate(
    () =>
      (globalThis as typeof globalThis & { __omniusLongTasks?: number[] }).__omniusLongTasks ?? [],
  );
  const measurements: RuntimeMeasurements = {
    startupRequests,
    applicationShellRenderMs,
    routeTransitionMs,
    apiWaterfallDepth: apiWaterfallDepth(apiTimings),
    longTaskCount: longTasks.length,
    longestTaskMs: Math.max(0, ...longTasks),
  };

  expect(measurements.startupRequests).toBeLessThanOrEqual(budget.runtime.startupRequests);
  expect(measurements.applicationShellRenderMs).toBeLessThanOrEqual(
    budget.runtime.applicationShellRenderMs,
  );
  expect(measurements.routeTransitionMs).toBeLessThanOrEqual(budget.runtime.routeTransitionMs);
  expect(measurements.apiWaterfallDepth).toBeLessThanOrEqual(budget.runtime.apiWaterfallDepth);
  expect(measurements.longTaskCount).toBeLessThanOrEqual(budget.runtime.longTasks.count);
  expect(measurements.longestTaskMs).toBeLessThanOrEqual(budget.runtime.longTasks.maxDurationMs);
  await writeFile(
    testInfo.outputPath("runtime-measurements.json"),
    `${JSON.stringify({ budget: budget.runtime, measured: measurements }, null, 2)}\n`,
  );
});
