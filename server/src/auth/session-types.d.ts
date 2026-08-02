import "express-session";

declare module "express-session" {
  interface SessionData {
    userId?: number;
    username?: string;
    role?: string;
    // Set once username+password check out but the account has 2FA
    // enabled - userId itself stays unset (requireAuth gates on it) until
    // /auth/login/verify-totp confirms the code, so a pending login can't
    // reach any authenticated route.
    pendingTotpUserId?: number;
    // Which scanner agents' results this user may see (server/src/auth/
    // scannerScope.ts) - absent/undefined means unrestricted (sees
    // everything), same as today's behavior for every existing account.
    // Loaded once at login, same trust/staleness model as role above.
    allowedScannerAgentIds?: string[];
  }
}
