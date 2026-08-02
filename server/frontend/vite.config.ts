import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/auth": "https://localhost:8443",
      "/api": "https://localhost:8443",
    },
  },
  build: {
    outDir: "dist",
  },
});
