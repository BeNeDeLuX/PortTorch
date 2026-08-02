import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    // Integration tests (tests/integration/*.integration.test.ts) need a
    // real Postgres and their own config (vitest.integration.config.ts,
    // `npm run test:integration`) - excluded here so the default `npm
    // test` stays fast and hermetic (no DB required).
    exclude: ["**/node_modules/**", "**/*.integration.test.ts"],
    // Imported transitively by several pure-logic modules via
    // src/config.ts, which throws at import time if these are missing
    // (see config.ts's required()) - none of these unit tests actually
    // connect to a database or start a server, but the module graph still
    // runs through config.ts, so it needs something present to parse.
    env: {
      DATABASE_URL: "postgres://test:test@localhost:5432/test",
      SESSION_SECRET: "test-session-secret",
    },
  },
});
