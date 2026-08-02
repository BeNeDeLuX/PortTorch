import { defineConfig } from "vitest/config";

// Points at the ephemeral test Postgres from docker-compose.yml's
// postgres-test service (`docker compose --profile test up -d
// postgres-test`, migrated via `DATABASE_URL=... npm run migrate:up`) -
// override via TEST_DATABASE_URL if running against something else.
const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? "postgres://porttorch_test:porttorch_test@localhost:5433/porttorch_test";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/integration/**/*.integration.test.ts"],
    // All integration test files share one real database - running them
    // in parallel would let one file's fixtures interfere with another's
    // (e.g. two files' excludes union queries seeing each other's global
    // excludes). Sequential is slower but avoids that class of flake.
    fileParallelism: false,
    testTimeout: 15000,
    env: {
      DATABASE_URL: TEST_DATABASE_URL,
      SESSION_SECRET: "test-session-secret-integration",
    },
  },
});
