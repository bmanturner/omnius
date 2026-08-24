import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const backend = process.env.RSK_BACKEND_URL ?? "http://127.0.0.1:3000";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: backend, changeOrigin: false },
      "/ws": { target: backend, ws: true, changeOrigin: false },
      "/events": { target: backend, changeOrigin: false },
    },
  },
  build: {
    manifest: true,
    sourcemap: false,
  },
});
