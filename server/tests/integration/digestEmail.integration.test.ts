import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { config } from "../../src/config";
import { tick } from "../../src/digest/emailDigest";
import { toDateOnlyString } from "../../src/lib/dateOnly";
import { closeDb } from "./helpers";

// digest_email_state is a singleton row (id = 1, see migration
// 1741100000000_epss_alert_and_digest_email.js) shared by the whole test
// database - save/restore both it and config.digestEmailHourUtc so this
// suite doesn't leave global state behind for whatever runs after it.
describe("daily digest email tick", () => {
  let originalLastSentDate: string | null;
  let originalHour: number;

  beforeAll(async () => {
    const row = await db.selectFrom("digest_email_state").select(["last_sent_date"]).where("id", "=", 1).executeTakeFirstOrThrow();
    originalLastSentDate = toDateOnlyString(row.last_sent_date);
    originalHour = config.digestEmailHourUtc;
  });

  afterAll(async () => {
    await db.updateTable("digest_email_state").set({ last_sent_date: originalLastSentDate }).where("id", "=", 1).execute();
    config.digestEmailHourUtc = originalHour;
    await closeDb();
  });

  it("is a no-op outside the configured hour", async () => {
    const currentHour = new Date().getUTCHours();
    config.digestEmailHourUtc = (currentHour + 12) % 24; // guaranteed not "now"
    await db.updateTable("digest_email_state").set({ last_sent_date: null }).where("id", "=", 1).execute();

    await tick();

    const row = await db.selectFrom("digest_email_state").select(["last_sent_date"]).where("id", "=", 1).executeTakeFirstOrThrow();
    expect(toDateOnlyString(row.last_sent_date)).toBeNull();
  });

  it("sends and records today's date once the configured hour is reached", async () => {
    const now = new Date();
    config.digestEmailHourUtc = now.getUTCHours();
    await db.updateTable("digest_email_state").set({ last_sent_date: null }).where("id", "=", 1).execute();

    await tick();

    const row = await db.selectFrom("digest_email_state").select(["last_sent_date"]).where("id", "=", 1).executeTakeFirstOrThrow();
    expect(toDateOnlyString(row.last_sent_date)).toBe(now.toISOString().slice(0, 10));
  });

  it("does not error or change state when already sent today", async () => {
    const now = new Date();
    const todayUtc = now.toISOString().slice(0, 10);
    config.digestEmailHourUtc = now.getUTCHours();
    await db.updateTable("digest_email_state").set({ last_sent_date: todayUtc }).where("id", "=", 1).execute();

    await expect(tick()).resolves.toBeUndefined();

    const row = await db.selectFrom("digest_email_state").select(["last_sent_date"]).where("id", "=", 1).executeTakeFirstOrThrow();
    expect(toDateOnlyString(row.last_sent_date)).toBe(todayUtc);
  });
});
