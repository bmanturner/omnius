import {
  access,
  mkdir,
  mkdtemp,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
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

const EMPTY_CORE_SOURCE = "/**\n * Generated application HTTP client.\n *\n * The initial application contract has no operations. Add application-owned routes to\n * contracts/openapi.json, then run the SDK generator to replace this empty namespace.\n */\nexport {};\n";
const EMPTY_REACT_QUERY_SOURCE = "/**\n * Generated application React Query client.\n *\n * The initial application contract has no operations. Add application-owned routes to\n * contracts/openapi.json, then run the SDK generator to replace this empty namespace.\n */\nexport {};\n";

const arguments_ = process.argv.slice(2);
const check = arguments_.length === 1 && arguments_[0] === "--check";
if (arguments_.length > 0 && !check) {
  throw new TypeError("Usage: node scripts/generate-http-client.mjs [--check]");
}
const includeReactQuery = await access(
  new URL("../src/react/index.ts", import.meta.url),
).then(
  () => true,
  (error) => {
    if (error?.code === "ENOENT") return false;
    throw error;
  },
);

const canonicalInput = await assertCanonicalOpenApiInput(
  CANONICAL_OPENAPI_INPUT,
  REPOSITORY_ROOT,
  CANONICAL_OPENAPI_INPUT,
);
const document = await readAndValidateCanonicalOpenApi(canonicalInput);
const hasApplicationPaths = Object.keys(document.paths).length > 0;

const generatedRoot = dirname(GENERATED_HTTP_DIRECTORY);
await mkdir(generatedRoot, { recursive: true });
const firstDirectory = await mkdtemp(join(generatedRoot, ".http-generation-"));
const secondDirectory = await mkdtemp(join(generatedRoot, ".http-generation-"));

async function generateInto(directory) {
  if (!hasApplicationPaths) {
    await writeFile(join(directory, "core.ts"), EMPTY_CORE_SOURCE, "utf8");
    if (includeReactQuery) {
      await writeFile(
        join(directory, "react-query.ts"),
        EMPTY_REACT_QUERY_SOURCE,
        "utf8",
      );
    }
    return;
  }

  const configuration = createTrustedOrvalConfig(directory, includeReactQuery);
  for (const project of Object.values(configuration)) {
    await generate(project, WEB_SDK_ROOT, {
      clean: false,
      failOnWarnings: true,
      throwOnError: true,
    });
  }
}

try {
  await generateInto(firstDirectory);
  await generateInto(secondDirectory);

  const nondeterministic = await findStaleGeneratedFiles(
    firstDirectory,
    secondDirectory,
  );
  if (nondeterministic.length > 0) {
    throw new Error(
      `HTTP generation is not deterministic: ${nondeterministic.join(", ")}`,
    );
  }

  if (check) {
    const stale = await findStaleGeneratedFiles(
      GENERATED_HTTP_DIRECTORY,
      firstDirectory,
    );
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
