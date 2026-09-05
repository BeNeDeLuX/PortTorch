// In-memory brute-force guard for /auth/login. Deliberately not
// DB-backed: this project's webserver is a single-instance deployment
// (see scheduler.ts's own note about the same assumption), so process
// memory is sufficient and avoids an extra table/query on every login
// attempt. State resets on webserver restart - acceptable for this
// threat model (slowing down/locking out repeated guessing), not meant
// to be a permanent ban list.
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60_000;
const LOCKOUT_MS = 15 * 60_000;

interface AttemptState {
  count: number;
  windowStartedAt: number;
  lockedUntil?: number;
}

const attempts = new Map<string, AttemptState>();

export function isLockedOut(key: string): boolean {
  const state = attempts.get(key);
  if (!state?.lockedUntil) return false;
  if (Date.now() > state.lockedUntil) {
    attempts.delete(key);
    return false;
  }
  return true;
}

/**
 * Records a failed attempt for `key`, returning true only on the attempt
 * that *causes* a lockout - never on the ones refused afterwards.
 *
 * That distinction is the whole reason it returns anything: a caller that
 * alerted on every refused attempt would send one message per guess for
 * the next fifteen minutes, which is how an alert worth reading becomes
 * one people filter away.
 */
export function recordFailure(key: string): boolean {
  const now = Date.now();
  const state = attempts.get(key);
  if (!state || now - state.windowStartedAt > WINDOW_MS) {
    attempts.set(key, { count: 1, windowStartedAt: now });
    return false;
  }
  state.count += 1;
  if (state.count >= MAX_ATTEMPTS && !state.lockedUntil) {
    state.lockedUntil = now + LOCKOUT_MS;
    return true;
  }
  return false;
}

export function recordSuccess(key: string): void {
  attempts.delete(key);
}
