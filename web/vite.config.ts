import { GENERATED_AGAINST_CONTRACT_HASH } from "@omnius/web-sdk/client";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import type { Plugin } from "vite";

function readBuildTimestamp(): string {
  const sourceDateEpoch = process.env.SOURCE_DATE_EPOCH;
  if (sourceDateEpoch === undefined) {
    return "development";
  }
  if (!/^\d+$/u.test(sourceDateEpoch)) {
    throw new Error("SOURCE_DATE_EPOCH must contain whole Unix seconds.");
  }
  return new Date(Number(sourceDateEpoch) * 1_000).toISOString();
}

function contractMetadataPlugin(): Plugin {
  return {
    name: "omnius-contract-metadata",
    transformIndexHtml(html) {
      return html.replaceAll(
        "__OMNIUS_CONTRACT_HASH_META__",
        GENERATED_AGAINST_CONTRACT_HASH,
      );
    },
  };
}

const buildRevision = process.env.OMNIUS_BUILD_REVISION ?? "development";
const buildTimestamp = readBuildTimestamp();

export default defineConfig({
  plugins: [contractMetadataPlugin(), react()],
  define: {
    __BUILD_REVISION__: JSON.stringify(buildRevision),
    __BUILD_TIMESTAMP__: JSON.stringify(buildTimestamp),
  },
  build: {
    manifest: true,
    sourcemap: true,
    target: "es2024",
    rollupOptions: {
      output: {
        entryFileNames: "assets/[name]-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
});
