import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const evidencePath = resolve(
  process.cwd(),
  process.argv[2] ??
    process.env.OMNIUS_ACCESSIBILITY_REVIEW_EVIDENCE ??
    "e2e/manual-accessibility-review.pending.json",
);

let evidence;
try {
  evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
} catch (error) {
  const detail = error instanceof Error ? error.message : String(error);
  throw new Error(`manual accessibility evidence is unreadable: ${detail}`);
}

function requireString(value, field) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`manual accessibility evidence requires ${field}`);
  }
  return value;
}

function requireIsoDate(value, field) {
  const date = requireString(value, field);
  if (Number.isNaN(Date.parse(date))) {
    throw new Error(`manual accessibility evidence requires an ISO date-time at ${field}`);
  }
}

function requirePassedScenarios(value, field) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`manual accessibility evidence requires scenarios at ${field}`);
  }
  for (const [index, scenario] of value.entries()) {
    requireString(scenario?.name, `${field}[${index}].name`);
    if (scenario?.result !== "passed") {
      throw new Error(`${field}[${index}] must record a manual pass`);
    }
    if (typeof scenario.notes !== "string") {
      throw new Error(`${field}[${index}].notes must be a string`);
    }
  }
}

if (evidence?.schemaVersion !== 2) {
  throw new Error("manual accessibility evidence must use schemaVersion 2");
}
if (evidence.status !== "approved") {
  throw new Error(
    "manual accessibility review is pending; a human keyboard and screen-reader review must approve release evidence",
  );
}
const binding = evidence.binding;
const revision = requireString(binding?.revision, "binding.revision");
if (!/^[a-f0-9]{7,64}$/iu.test(revision)) {
  throw new Error("manual accessibility evidence revision must be a 7-64 character Git SHA");
}
for (const field of ["specManifestSha256", "contractAggregateSha256"]) {
  const hash = requireString(binding?.[field], `binding.${field}`);
  if (!/^[a-f0-9]{64}$/u.test(hash)) {
    throw new Error(`manual accessibility evidence requires a SHA-256 digest at binding.${field}`);
  }
}
requireString(binding?.runId, "binding.runId");
const expectedRevision = process.env.OMNIUS_GIT_REVISION;
if (expectedRevision !== undefined && revision.toLowerCase() !== expectedRevision.toLowerCase()) {
  throw new Error("manual accessibility evidence revision does not match OMNIUS_GIT_REVISION");
}
requireIsoDate(evidence.reviewedAt, "reviewedAt");
requireString(evidence.reviewer, "reviewer");
requireString(evidence.keyboard?.browser, "keyboard.browser");
requireString(evidence.keyboard?.operatingSystem, "keyboard.operatingSystem");
requirePassedScenarios(evidence.keyboard?.scenarios, "keyboard.scenarios");
requireString(evidence.screenReader?.assistiveTechnology, "screenReader.assistiveTechnology");
requireString(
  evidence.screenReader?.assistiveTechnologyVersion,
  "screenReader.assistiveTechnologyVersion",
);
requireString(evidence.screenReader?.browser, "screenReader.browser");
requireString(evidence.screenReader?.operatingSystem, "screenReader.operatingSystem");
requirePassedScenarios(evidence.screenReader?.scenarios, "screenReader.scenarios");
if (!Array.isArray(evidence.findings) || evidence.findings.length !== 0) {
  throw new Error("approved manual accessibility evidence cannot contain unresolved findings");
}
if (evidence.approval?.approved !== true) {
  throw new Error("manual accessibility evidence requires explicit approval");
}
requireString(evidence.approval.approvedBy, "approval.approvedBy");
requireIsoDate(evidence.approval.approvedAt, "approval.approvedAt");

process.stdout.write(`manual accessibility evidence approved for ${revision}\n`);
