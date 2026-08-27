import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = path.join(packageRoot, "src");
const packageJson = JSON.parse(await readFile(path.join(packageRoot, "package.json"), "utf8"));
const publicEntries = [
  "client",
  "auth",
  "authorization",
  "realtime",
  "uploads",
  "capabilities",
  "react",
  "testing",
];
const actualExportNames = Object.keys(packageJson.exports ?? {}).sort();
const expectedExportNames = publicEntries.map((entry) => `./${entry}`).sort();
if (JSON.stringify(actualExportNames) !== JSON.stringify(expectedExportNames)) {
  throw new Error(
    `SDK export map must contain only documented subpaths. Expected ${expectedExportNames.join(", ")}; received ${actualExportNames.join(", ")}.`,
  );
}

for (const entry of publicEntries) {
  const exportDefinition = packageJson.exports[`./${entry}`];
  const expectedDefinition = {
    types: `./dist/${entry}/index.d.ts`,
    import: `./dist/${entry}/index.js`,
  };
  if (JSON.stringify(exportDefinition) !== JSON.stringify(expectedDefinition)) {
    throw new Error(`Export ./${entry} must expose only its declaration and ESM entry files.`);
  }
}

const neutralEntries = publicEntries.filter((entry) => entry !== "react");
const visited = new Set();
async function inspectNeutralModule(fileName, publicEntry) {
  if (visited.has(fileName)) {
    return;
  }
  visited.add(fileName);
  const source = await readFile(fileName, "utf8");
  const imports = ts.preProcessFile(source, true, true).importedFiles.map(
    (importedFile) => importedFile.fileName,
  );
  for (const moduleSpecifier of imports) {
    if (moduleSpecifier === "react" || moduleSpecifier.startsWith("react/")) {
      throw new Error(`Neutral entry ./${publicEntry} reaches React through ${fileName}.`);
    }
    if (!moduleSpecifier.startsWith(".")) {
      continue;
    }

    const sourceSpecifier = moduleSpecifier.endsWith(".js")
      ? `${moduleSpecifier.slice(0, -3)}.ts`
      : moduleSpecifier;
    const importedPath = path.resolve(path.dirname(fileName), sourceSpecifier);
    const relativePath = path.relative(sourceRoot, importedPath);
    if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
      throw new Error(`Neutral entry ./${publicEntry} imports source outside the package: ${moduleSpecifier}.`);
    }
    if (relativePath === "react/index.ts" || relativePath.startsWith(`react${path.sep}`)) {
      throw new Error(`Neutral entry ./${publicEntry} reaches the React adapter.`);
    }
    await inspectNeutralModule(importedPath, publicEntry);
  }
}

for (const entry of neutralEntries) {
  await inspectNeutralModule(path.join(sourceRoot, entry, "index.ts"), entry);
}
