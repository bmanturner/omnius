import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const arguments_ = process.argv.slice(2);
const check = arguments_.length === 1 && arguments_[0] === "--check";
if (arguments_.length > 0 && !check) {
  throw new TypeError("Usage: node scripts/sync-contracts.mjs [--check]");
}

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const contractsRoot = join(projectRoot, "contracts");
const sdkRoot = join(projectRoot, "packages/web-sdk");
const statePath = join(projectRoot, ".omnius/service.toml");
const utf8 = "utf8";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function prettyJson(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, utf8);
}

function tomlString(source, section, key) {
  const sectionPattern = new RegExp(
    `(?:^|\\n)\\[${section.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}\\]\\s*\\n([\\s\\S]*?)(?=\\n\\[|$)`,
    "u",
  );
  const sectionMatch = source.match(sectionPattern);
  if (sectionMatch === null) throw new Error(`Missing [${section}] in ${statePath}.`);
  const keyMatch = sectionMatch[1].match(new RegExp(`^${key}\\s*=\\s*"([^"]+)"\\s*$`, "mu"));
  if (keyMatch === null) throw new Error(`Missing ${section}.${key} in ${statePath}.`);
  return keyMatch[1];
}

function serviceMetadata(source) {
  const modules = [];
  const modulePattern = /(?:^|\n)\[\[modules\]\]\s*\n([\s\S]*?)(?=\n\[|$)/gu;
  for (const match of source.matchAll(modulePattern)) {
    const id = match[1].match(/^id\s*=\s*"([^"]+)"\s*$/mu)?.[1];
    const version = match[1].match(/^version\s*=\s*"([^"]+)"\s*$/mu)?.[1];
    if (id === undefined || version === undefined) {
      throw new Error(`Invalid [[modules]] entry in ${statePath}.`);
    }
    modules.push({ id, version });
  }
  if (modules.length === 0) throw new Error(`No [[modules]] entries in ${statePath}.`);
  if (new Set(modules.map(({ id }) => id)).size !== modules.length) {
    throw new Error(`Duplicate module metadata in ${statePath}.`);
  }
  return {
    frameworkVersion: tomlString(source, "framework", "version"),
    profile: tomlString(source, "profile", "id"),
    profileVersion: tomlString(source, "profile", "version"),
    modules,
  };
}

function run(command, args, cwd) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd, stdio: "inherit" });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolvePromise();
      } else {
        reject(
          new Error(
            `${command} ${args.join(" ")} failed${signal === null ? ` with exit code ${String(code)}` : ` from signal ${signal}`}.`,
          ),
        );
      }
    });
  });
}

async function filesUnder(root, prefix = "") {
  const paths = [];
  for (const entry of await readdir(join(root, prefix), { withFileTypes: true })) {
    const path = join(prefix, entry.name);
    if (entry.isDirectory()) paths.push(...(await filesUnder(root, path)));
    else if (entry.isFile()) paths.push(path);
  }
  return paths.sort();
}

async function compareFile(expected, actual, label) {
  const [expectedBytes, actualBytes] = await Promise.all([
    readFile(expected),
    readFile(actual).catch((error) => {
      if (error?.code === "ENOENT") return null;
      throw error;
    }),
  ]);
  if (actualBytes === null || !expectedBytes.equals(actualBytes)) return label;
  return null;
}

const temporaryRoot = await mkdtemp(join(tmpdir(), "reading-list-contracts-"));
try {
  const stagedContracts = join(temporaryRoot, "contracts");
  const stagedSdk = join(temporaryRoot, "packages/web-sdk");
  await mkdir(stagedContracts, { recursive: true });

  await run(
    "cargo",
    [
      "run",
      "--locked",
      "--manifest-path",
      join(projectRoot, "Cargo.toml"),
      "--bin",
      "reading-list",
      "--",
      "contracts",
      "--output",
      join(stagedContracts, "openapi.json"),
    ],
    projectRoot,
  );

  const [openapiBytes, permissionsBytes, stateSource, manifestSource, capabilitiesSource, packageSource] =
    await Promise.all([
      readFile(join(stagedContracts, "openapi.json")),
      readFile(join(contractsRoot, "permissions.json")),
      readFile(statePath, utf8),
      readFile(join(contractsRoot, "contract-manifest.json"), utf8),
      readFile(join(contractsRoot, "capabilities.json"), utf8),
      readFile(join(projectRoot, "package.json"), utf8),
    ]);
  JSON.parse(openapiBytes.toString(utf8));
  JSON.parse(permissionsBytes.toString(utf8));

  const metadata = serviceMetadata(stateSource);
  const applicationVersion = JSON.parse(packageSource).version;
  if (typeof applicationVersion !== "string" || applicationVersion.length === 0) {
    throw new Error(`Missing package version in ${join(projectRoot, "package.json")}.`);
  }

  const aggregate = sha256(Buffer.concat([openapiBytes, permissionsBytes]));
  const capabilities = JSON.parse(capabilitiesSource);
  capabilities.contract_hash = `sha256:${aggregate}`;
  capabilities.profile = metadata.profile;
  capabilities.service_version = applicationVersion;
  const capabilitiesBytes = prettyJson(capabilities);

  const manifest = JSON.parse(manifestSource);
  manifest.aggregate_sha256 = aggregate;
  manifest.application_version = applicationVersion;
  manifest.modules = metadata.modules.map(({ id }) => id);
  manifest.profile = metadata.profile;
  manifest.service_kit_version = metadata.frameworkVersion;
  manifest.generators = {
    contracts: `reading-list-contract-sync/${applicationVersion}`,
    openapi: `reading-list/${applicationVersion}`,
  };
  manifest.contracts = [
    {
      path: "contracts/capabilities.json",
      required: true,
      sha256: sha256(capabilitiesBytes),
    },
    {
      path: "contracts/openapi.json",
      required: true,
      sha256: sha256(openapiBytes),
    },
    {
      path: "contracts/permissions.json",
      required: true,
      sha256: sha256(permissionsBytes),
    },
  ];
  const manifestBytes = prettyJson(manifest);

  await Promise.all([
    writeFile(join(stagedContracts, "capabilities.json"), capabilitiesBytes),
    writeFile(join(stagedContracts, "contract-manifest.json"), manifestBytes),
    writeFile(join(stagedContracts, "permissions.json"), permissionsBytes),
    cp(sdkRoot, stagedSdk, { recursive: true }),
  ]);

  await run("pnpm", ["run", "generate"], stagedSdk);

  const contractFiles = [
    "capabilities.json",
    "contract-manifest.json",
    "openapi.json",
    "permissions.json",
  ];
  const generatedRoot = join(stagedSdk, "src/internal/generated");
  const generatedFiles = await filesUnder(generatedRoot);

  if (check) {
    const comparisons = [
      ...contractFiles.map((path) =>
        compareFile(join(stagedContracts, path), join(contractsRoot, path), `contracts/${path}`),
      ),
      ...generatedFiles.map((path) =>
        compareFile(
          join(generatedRoot, path),
          join(sdkRoot, "src/internal/generated", path),
          `packages/web-sdk/src/internal/generated/${path}`,
        ),
      ),
    ];
    const drift = (await Promise.all(comparisons)).filter((path) => path !== null);
    const checkedGenerated = await filesUnder(join(sdkRoot, "src/internal/generated"));
    for (const path of checkedGenerated) {
      if (!generatedFiles.includes(path)) {
        drift.push(`packages/web-sdk/src/internal/generated/${path}`);
      }
    }
    if (drift.length > 0) {
      throw new Error(`Contract artifacts are stale:\n${[...new Set(drift)].sort().map((path) => `  ${path}`).join("\n")}\nRun pnpm contracts:sync.`);
    }
    console.log("Contract artifacts are current.");
  } else {
    for (const path of contractFiles) {
      await writeFile(join(contractsRoot, path), await readFile(join(stagedContracts, path)));
    }
    await rm(join(sdkRoot, "src/internal/generated"), { recursive: true, force: true });
    await mkdir(join(sdkRoot, "src/internal"), { recursive: true });
    await cp(generatedRoot, join(sdkRoot, "src/internal/generated"), { recursive: true });
    console.log(
      `Synchronized contracts for profile ${metadata.profile}@${metadata.profileVersion} and ${String(metadata.modules.length)} modules.`,
    );
  }
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
