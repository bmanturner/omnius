import { readFile, readdir, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

const HTTP_OPERATION_METHODS: Readonly<Record<string, true>> = Object.freeze({
  get: true,
  put: true,
  post: true,
  delete: true,
  options: true,
  head: true,
  patch: true,
  trace: true,
});

type JsonObject = Record<string, unknown>;

function pathIsInside(root: string, candidate: string): boolean {
  const pathFromRoot = relative(root, candidate);
  return (
    pathFromRoot.length === 0 ||
    (!isAbsolute(pathFromRoot) && pathFromRoot !== ".." && !pathFromRoot.startsWith(`..${sep}`))
  );
}

function comparePaths(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export async function assertCanonicalOpenApiInput(
  candidate: string | URL,
  repositoryRoot: string,
  canonicalInput: string,
): Promise<string> {
  if (candidate instanceof URL || /^[a-z][a-z0-9+.-]*:\/\//iu.test(candidate)) {
    throw new TypeError("HTTP client generation rejects URL inputs.");
  }
  const repository = await realpath(repositoryRoot);
  const canonical = await realpath(canonicalInput);
  const selected = await realpath(resolve(repository, candidate));
  if (!pathIsInside(repository, selected)) {
    throw new TypeError("HTTP client generation rejects inputs outside the repository.");
  }
  if (selected !== canonical) {
    throw new TypeError("HTTP client generation accepts only contracts/openapi.json.");
  }
  return selected;
}

function resolveJsonPointer(document: JsonObject, reference: string): unknown {
  let current: unknown = document;
  for (const encodedSegment of reference.slice(2).split("/")) {
    if (/~(?:[^01]|$)/u.test(encodedSegment)) {
      throw new TypeError(`OpenAPI reference uses an invalid JSON pointer escape: ${reference}`);
    }
    const segment = encodedSegment.replaceAll("~1", "/").replaceAll("~0", "~");
    if (typeof current !== "object" || current === null || Array.isArray(current)) {
      throw new TypeError(`OpenAPI reference is unresolved: ${reference}`);
    }
    const object = current as JsonObject;
    if (!Object.hasOwn(object, segment)) {
      throw new TypeError(`OpenAPI reference is unresolved: ${reference}`);
    }
    current = object[segment];
  }
  return current;
}

function validateReferences(document: JsonObject): void {
  const pending: unknown[] = [document];
  while (pending.length > 0) {
    const value = pending.pop();
    if (Array.isArray(value)) {
      pending.push(...value);
      continue;
    }
    if (typeof value !== "object" || value === null) {
      continue;
    }
    const object = value as JsonObject;
    const reference = object.$ref;
    if (reference !== undefined) {
      if (typeof reference !== "string" || !reference.startsWith("#/")) {
        throw new TypeError("OpenAPI external and non-local references are not allowed.");
      }
      resolveJsonPointer(document, reference);
    }
    pending.push(...Object.values(object));
  }
}

/** Performs deterministic trust-boundary checks before Orval parses the schema. */
export function validateCanonicalOpenApiDocument(value: unknown): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Canonical OpenAPI input must be a JSON object.");
  }
  const document = value as JsonObject;
  if (typeof document.openapi !== "string" || !/^3\.1\.[0-9]+$/u.test(document.openapi)) {
    throw new TypeError("HTTP generation supports canonical OpenAPI 3.1 documents only.");
  }
  if (typeof document.paths !== "object" || document.paths === null || Array.isArray(document.paths)) {
    throw new TypeError("Canonical OpenAPI input must define a paths object.");
  }
  if (
    typeof document.components !== "object" ||
    document.components === null ||
    Array.isArray(document.components)
  ) {
    throw new TypeError("Canonical OpenAPI input must define a components object.");
  }

  const operationIds = new Set<string>();
  for (const [path, pathValue] of Object.entries(document.paths as JsonObject)) {
    if (!path.startsWith("/") || typeof pathValue !== "object" || pathValue === null) {
      throw new TypeError(`OpenAPI path item is invalid: ${path}`);
    }
    const pathItem = pathValue as JsonObject;
    for (const [method, operationValue] of Object.entries(pathItem)) {
      if (HTTP_OPERATION_METHODS[method.toLowerCase()] !== true) {
        continue;
      }
      if (typeof operationValue !== "object" || operationValue === null) {
        throw new TypeError(`OpenAPI operation is invalid: ${method.toUpperCase()} ${path}`);
      }
      const operationId = (operationValue as JsonObject).operationId;
      if (typeof operationId !== "string" || operationId.length === 0) {
        throw new TypeError(`OpenAPI operation is missing operationId: ${method.toUpperCase()} ${path}`);
      }
      if (operationIds.has(operationId)) {
        throw new TypeError(`OpenAPI operationId is duplicated: ${operationId}`);
      }
      operationIds.add(operationId);
    }
  }
  validateReferences(document);
}

export async function readAndValidateCanonicalOpenApi(path: string): Promise<Readonly<JsonObject>> {
  const source = await readFile(path, "utf8");
  let document: unknown;
  try {
    document = JSON.parse(source) as unknown;
  } catch (error: unknown) {
    throw new TypeError("Canonical OpenAPI input is not valid JSON.", { cause: error });
  }
  validateCanonicalOpenApiDocument(document);
  return document as Readonly<JsonObject>;
}

async function collectFiles(root: string, directory = root): Promise<Map<string, Uint8Array>> {
  const files = new Map<string, Uint8Array>();
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => comparePaths(left.name, right.name));
  for (const entry of entries) {
    const absolute = resolve(directory, entry.name);
    if (entry.isSymbolicLink()) {
      throw new TypeError(`Generated output must not contain symbolic links: ${absolute}`);
    }
    if (entry.isDirectory()) {
      const nested = await collectFiles(root, absolute);
      for (const [path, content] of nested) {
        files.set(path, content);
      }
      continue;
    }
    if (!entry.isFile()) {
      throw new TypeError(`Generated output contains an unsupported entry: ${absolute}`);
    }
    files.set(relative(root, absolute), await readFile(absolute));
  }
  return files;
}

/** Returns stable relative paths that are missing, extra, or byte-different. */
export async function findStaleGeneratedFiles(
  expectedDirectory: string,
  generatedDirectory: string,
): Promise<readonly string[]> {
  let expected: Map<string, Uint8Array>;
  try {
    expected = await collectFiles(expectedDirectory);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      expected = new Map();
    } else {
      throw error;
    }
  }
  const generated = await collectFiles(generatedDirectory);
  const paths = new Set([...expected.keys(), ...generated.keys()]);
  const stale: string[] = [];
  for (const path of [...paths].sort(comparePaths)) {
    const expectedContent = expected.get(path);
    const generatedContent = generated.get(path);
    if (
      expectedContent === undefined ||
      generatedContent === undefined ||
      !Buffer.from(expectedContent).equals(Buffer.from(generatedContent))
    ) {
      stale.push(path);
    }
  }
  return Object.freeze(stale);
}
