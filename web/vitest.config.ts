import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  define: {
    __BUILD_REVISION__: JSON.stringify("test"),
    __BUILD_TIMESTAMP__: JSON.stringify("reproducible"),
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./test/setup.ts"],
    restoreMocks: true,
    clearMocks: true,
    sequence: { concurrent: false },
  },
});
