import { defineConfig } from "orval";

export default defineConfig({
  compatibility: {
    input: {
      target: "../../contracts/openapi.json",
      unsafeDisableValidation: false,
      parserOptions: {
        externalRefs: {
          allow: [],
        },
      },
    },
    output: {
      target: "./generated/client.ts",
      client: "react-query",
      clean: true,
      mode: "single",
      mock: false,
      override: {
        mutator: {
          path: "./src/mutator.ts",
          name: "compatibilityMutator",
        },
      },
    },
  },
});
