import { config } from "../config";

// Throughput limiting for the External API, keyed by token.
//
// Deliberately a different shape from auth/rateLimiter.ts, which is a
// lockout-after-N-failures brute-force guard: nothing here is a failed
// authentication. These are successful, authorised calls, and the risk is
// a runaway or misconfigured SOAR integration polling /hosts/lookup in a
// tight loop - every one of those runs real fleet-wide SQL, so an
// unbounded caller degrades the dashboard for everyone. A failure-based
// limiter can't see that at all.
//
// In-memory, same single-instance assumption already documented in
// auth/rateLimiter.ts and scheduler.ts. State resets on restart, which is
// fine for smoothing out a runaway client rather than enforcing a quota.
//
// Keyed on the token, not the source IP: a token is the actual identity
// here (several tools may share an egress IP, and one token may be used
// from several), and it's also what an operator can revoke in response.
interface WindowState {
  count: number;
  windowStartedAt: number;
}

const windows = new Map<string, WindowState>();

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  // Unix ms when the current window rolls over.
  resetAt: number;
}

export function checkApiTokenRateLimit(tokenId: string, now: number = Date.now()): RateLimitResult {
  const limit = config.apiTokenRateLimitPerMinute;
  const windowMs = 60_000;

  // 0 (or negative) disables the limiter entirely - an escape hatch for a
  // deployment whose own automation legitimately exceeds any default we
  // could pick, so the answer is never "patch the source".
  if (limit <= 0) {
    return { allowed: true, limit: 0, remaining: 0, resetAt: now + windowMs };
  }

  const state = windows.get(tokenId);
  if (!state || now - state.windowStartedAt >= windowMs) {
    windows.set(tokenId, { count: 1, windowStartedAt: now });
    return { allowed: true, limit, remaining: limit - 1, resetAt: now + windowMs };
  }

  state.count++;
  const resetAt = state.windowStartedAt + windowMs;
  if (state.count > limit) {
    return { allowed: false, limit, remaining: 0, resetAt };
  }
  return { allowed: true, limit, remaining: limit - state.count, resetAt };
}

// Only for tests - the map is process-global, so a test that exhausts a
// limit would otherwise leak that state into the next one.
export function resetApiTokenRateLimits(): void {
  windows.clear();
}
