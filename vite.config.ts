import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Vite serves `frontend/`; Tauri loads it from devUrl in dev and frontend/dist in release.
export default defineConfig({
  root: "frontend",
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
    chunkSizeWarningLimit: 1200,
  },
  test: {
    root: ".",
    include: ["frontend/src/**/*.test.ts"],
    environment: "node",
  },
});
