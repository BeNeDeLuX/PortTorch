import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { config } from "../config";
import type { Database } from "./types";

export const pgPool = new Pool({ connectionString: config.databaseUrl });

export const db = new Kysely<Database>({
  dialect: new PostgresDialect({ pool: pgPool }),
});
