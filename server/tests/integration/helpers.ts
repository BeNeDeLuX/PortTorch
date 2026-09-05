import crypto from "crypto";
import type { Express } from "express";
import request from "supertest";
import { buildApp } from "../../src/app";
import { db, pgPool } from "../../src/db";
import { hashPassword } from "../../src/auth/password";
import { hashApiKey } from "../../src/ingest/apiKeyAuth";

let app: Express | undefined;

export function getApp(): Express {
  if (!app) {
    app = buildApp();
  }
  return app;
}

// Every integration test file ends its suite with this so the pg pool
// doesn't keep vitest's process alive after the last test finishes.
export async function closeDb(): Promise<void> {
  await pgPool.end();
}

function uniqueSuffix(): string {
  return crypto.randomBytes(4).toString("hex");
}

export interface TestUser {
  id: number;
  username: string;
  password: string;
}

export async function createTestUser(role: "admin" | "operator" | "user", password = "correct-horse-battery-9"): Promise<TestUser> {
  const username = `it-${role}-${uniqueSuffix()}`;
  const passwordHash = await hashPassword(password);
  const user = await db
    .insertInto("users")
    .values({ username, password_hash: passwordHash, role })
    .returning(["id"])
    .executeTakeFirstOrThrow();
  return { id: user.id, username, password };
}

export async function deleteTestUser(id: number): Promise<void> {
  await db.deleteFrom("users").where("id", "=", id).execute();
}

export interface TestAgent {
  id: string;
  name: string;
  apiKey: string;
}

export async function createTestAgent(namePrefix = "it-agent"): Promise<TestAgent> {
  const name = `${namePrefix}-${uniqueSuffix()}`;
  const apiKey = crypto.randomBytes(32).toString("hex");
  const agent = await db
    .insertInto("scanner_agents")
    .values({ name, api_key_hash: hashApiKey(apiKey) })
    .returning(["id"])
    .executeTakeFirstOrThrow();
  return { id: agent.id, name, apiKey };
}

export async function deleteTestAgent(id: string): Promise<void> {
  await db.deleteFrom("scanner_agents").where("id", "=", id).execute();
}

export interface TestApiToken {
  id: string;
  name: string;
  token: string;
}

export async function createTestApiToken(namePrefix = "it-token"): Promise<TestApiToken> {
  const name = `${namePrefix}-${uniqueSuffix()}`;
  const token = crypto.randomBytes(32).toString("hex");
  const row = await db
    .insertInto("api_tokens")
    .values({ name, token_hash: hashApiKey(token) })
    .returning(["id"])
    .executeTakeFirstOrThrow();
  return { id: row.id, name, token };
}

export async function deleteTestApiToken(id: string): Promise<void> {
  await db.deleteFrom("api_tokens").where("id", "=", id).execute();
}

export interface SessionClient {
  get(path: string): request.Test;
  post(path: string): request.Test;
  patch(path: string): request.Test;
  put(path: string): request.Test;
  delete(path: string): request.Test;
}

// supertest's own request.agent() cookie jar won't resend a Secure-flagged
// cookie over what it perceives as a plain-http connection - that's
// actually *correct*, browser-faithful behavior (confirmed by testing
// both ways, not assumed), it just means these tests can't rely on it
// the way a browser session would work over real TLS. Instead: log in
// once (with X-Forwarded-Proto: https so express-session's secure-cookie
// check passes - app.set("trust proxy", 1) already trusts that header in
// production, e.g. behind a real reverse proxy), extract the cookie from
// the Set-Cookie response ourselves, and attach it manually on every
// subsequent call.
export async function loginAs(username: string, password: string): Promise<SessionClient> {
  const res = await request(getApp())
    .post("/auth/login")
    .set("X-Forwarded-Proto", "https")
    .send({ username, password });
  if (res.status !== 200 || !("username" in res.body)) {
    throw new Error(`login as ${username} failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
  const setCookie = res.headers["set-cookie"] as unknown as string[] | undefined;
  if (!setCookie?.length) {
    throw new Error(`login as ${username} did not set a session cookie`);
  }
  const cookie = setCookie[0].split(";")[0];

  return {
    get: (path: string) => request(getApp()).get(path).set("Cookie", cookie),
    post: (path: string) => request(getApp()).post(path).set("Cookie", cookie),
    patch: (path: string) => request(getApp()).patch(path).set("Cookie", cookie),
    put: (path: string) => request(getApp()).put(path).set("Cookie", cookie),
    delete: (path: string) => request(getApp()).delete(path).set("Cookie", cookie),
  };
}
