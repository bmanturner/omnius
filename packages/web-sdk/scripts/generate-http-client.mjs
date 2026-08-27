import { mkdir, mkdtemp, rename, rm } from "node:fs/promises";
import { dirname, join, relative } from "node:path";

import { generate } from "orval";

import {
  CANONICAL_OPENAPI_INPUT,
  GENERATED_HTTP_DIRECTORY,
  GENERATED_HTTP_TARGET,
  REPOSITORY_ROOT,
  WEB_SDK_ROOT,
  createTrustedOrvalConfig,
} from "../orval.config.ts";
import {
  assertCanonicalOpenApiInput,
  findStaleGeneratedFiles,
  readAndValidateCanonicalOpenApi,
} from "./http-generation.ts";

const arguments_ = process.argv.slice(2);
const check = arguments_.length === 1 && arguments_[0] === "--check";
if (arguments_.length > 0 && !check) {
  throw new TypeError("Usage: node scripts/generate-http-client.mjs [--check]");
}

const canonicalInput = await assertCanonicalOpenApiInput(
  CANONICAL_OPENAPI_INPUT,
  REPOSITORY_ROOT,
  CANONICAL_OPENAPI_INPUT,
);
await readAndValidateCanonicalOpenApi(canonicalInput);

const generatedRoot = dirname(GENERATED_HTTP_DIRECTORY);
await mkdir(generatedRoot, { recursive: true });
const firstDirectory = await mkdtemp(join(generatedRoot, ".http-generation-"));
const secondDirectory = await mkdtemp(join(generatedRoot, ".http-generation-"));

try {
  for (const directory of [firstDirectory, secondDirectory]) {
    const configuration = createTrustedOrvalConfig(directory);
    for (const project of [configuration.serviceHttp, configuration.serviceReactQuery]) {
      await generate(project, WEB_SDK_ROOT, {
        clean: false,
        failOnWarnings: true,
        throwOnError: true,
      });
    }
  }

  const nondeterministic = await findStaleGeneratedFiles(firstDirectory, secondDirectory);
  if (nondeterministic.length > 0) {
    throw new Error(
      `Orval generation is not deterministic: ${nondeterministic.join(", ")}`,
    );
  }

  if (check) {
    const stale = await findStaleGeneratedFiles(GENERATED_HTTP_DIRECTORY, firstDirectory);
    if (stale.length > 0) {
      throw new Error(
        `Generated HTTP client is stale: ${stale.join(", ")}. Run pnpm sdk:generate.`,
      );
    }
    console.log("Generated HTTP client is current.");
  } else {
    await rm(GENERATED_HTTP_DIRECTORY, { recursive: true, force: true });
    await rename(firstDirectory, GENERATED_HTTP_DIRECTORY);
    console.log(
      `Generated ${relative(REPOSITORY_ROOT, GENERATED_HTTP_TARGET)} from contracts/openapi.json.`,
    );
  }
} finally {
  await rm(firstDirectory, { recursive: true, force: true });
  await rm(secondDirectory, { recursive: true, force: true });
}
