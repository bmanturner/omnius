import { defineConfig } from "orval";

export default defineConfig({
  service: {
    input: {
      target: "../../contracts/openapi.json",
      validation: true,
    },
    output: {
      target: "./src/generated/http/client.ts",
      schemas: "./src/generated/http/model",
      client: "react-query",
      httpClient: "fetch",
      mode: "tags-split",
      clean: true,
      prettier: false,
      override: {
        mutator: {
          path: "./src/client/fetcher.ts",
          name: "serviceFetcher",
        },
      },
    },
  },
});
