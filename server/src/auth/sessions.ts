import { sql } from "kysely";
import { db } from "../db";
import { logger } from "../logger";

// Terminating a specific account's sessions.
//
// An earlier version of the password-change route claimed this wasn't
// practical ("independent store entries, no user index"). That was simply
// wrong: the store is connect-pg-simple, so sessions are rows in the
// `session` table with the serialized session in `sess`, and finishLogin
// puts userId in there - which makes them perfectly addressable. The
// consequence of believing otherwise was real: an admin resetting the
// password of an account they believe is compromised did not actually
// lock the attacker out, since that existing session survived untouched.
//
// Raw SQL because `session` is owned by connect-pg-simple, not by our
// migrations' schema, and isn't in db/types.ts - deliberately not added
// there either, so nothing else starts treating it as an application
// table.
//
// exceptSid keeps one session alive - used by the self-service password
// change, where signing out the person who just proved they know the
// current password would be pure friction. An admin reset passes nothing,
// because there the whole point is that every existing session is
// suspect.
export async function revokeUserSessions(userId: number, exceptSid?: string): Promise<number> {
  try {
    const result = await sql<{ sid: string }>`
      DELETE FROM session
      WHERE (sess->>'userId')::int = ${userId}
        ${exceptSid ? sql`AND sid <> ${exceptSid}` : sql``}
      RETURNING sid
    `.execute(db);
    return result.rows.length;
  } catch (err) {
    // Best-effort, like recordAudit: a failure here must not turn a
    // successful password change into a 500. It is logged loudly though -
    // unlike a missed audit line, a session that outlives its revocation
    // is a security-relevant outcome, not just a lost record.
    logger.error({
      event: "auth.session_revocation_failed",
      user_id: userId,
      err: err instanceof Error ? err.message : String(err),
    });
    return 0;
  }
}
