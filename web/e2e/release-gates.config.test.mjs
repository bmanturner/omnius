import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import test from "node:test";

const browserSupport = JSON.parse(readFileSync("browser-support.json", "utf8"));
const performanceBudget = JSON.parse(readFileSync("e2e/performance-budget.json", "utf8"));
const pendingReview = JSON.parse(
  readFileSync("e2e/manual-accessibility-review.pending.json", "utf8"),
);

test("browser matrix declares one full and two smoke release tiers", () => {
  assert.deepEqual(
    browserSupport.browsers.map(({ project, supportTier }) => ({ project, supportTier })),
    [
      { project: "chromium", supportTier: "full" },
      { project: "firefox", supportTier: "smoke" },
      { project: "webkit", supportTier: "smoke" },
    ],
  );
  for (const browser of browserSupport.browsers) {
    assert.ok(browser.coverage.length >= 4, `${browser.project} needs meaningful declared coverage`);
  }
});

test("every normative bundle and runtime measurement has a positive configurable budget", () => {
  assert.equal(performanceBudget.schemaVersion, 1);
  for (const name of [
    "entryJavaScriptBytes",
    "routeChunkBytes",
    "totalJavaScriptBytes",
    "totalCssBytes",
  ]) {
    assert.ok(performanceBudget.bundle[name] > 0, `missing bundle budget: ${name}`);
  }
  for (const name of [
    "startupRequests",
    "applicationShellRenderMs",
    "routeTransitionMs",
    "apiWaterfallDepth",
  ]) {
    assert.ok(performanceBudget.runtime[name] > 0, `missing runtime budget: ${name}`);
  }
  assert.ok(performanceBudget.runtime.longTasks.count >= 0);
  assert.ok(performanceBudget.runtime.longTasks.maxDurationMs > 0);
});

test("the committed manual evidence is explicitly pending and the release gate rejects it", () => {
  assert.equal(pendingReview.status, "pending");
  assert.equal(pendingReview.approval.approved, false);
  const gate = spawnSync(process.execPath, ["e2e/check-manual-accessibility-review.mjs"], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  assert.notEqual(gate.status, 0);
  assert.match(gate.stderr, /manual accessibility review is pending/u);
});
