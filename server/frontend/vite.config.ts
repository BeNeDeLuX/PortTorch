import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies API calls to a locally running webserver, which
// always serves HTTPS with a certificate it generated for itself on first
// boot (src/tls/generateCert.ts) - there is no plain-HTTP mode. Node
// rejects that certificate by default, so without `secure: false` every
// proxied request fails with "self-signed certificate" and the dev server
// can't even log in. Only ever applies to this dev-time proxy; nothing
// about how the built app talks to a real deployment.
const apiProxy = { target: "https://localhost:8443", secure: false, changeOrigin: true };

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/auth": apiProxy,
      "/api": apiProxy,
    },
  },
  build: {
    outDir: "dist",
  },
});
