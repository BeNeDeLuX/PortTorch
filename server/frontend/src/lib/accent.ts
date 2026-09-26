// The user-selectable accent colour, mirroring lib/theme.ts exactly
// (data-accent attribute + localStorage, applied before first paint in
// main.tsx). One CSS custom property (--accent in styles.css) is where
// every button/link/highlight colour in this app comes from.

// The single source of truth for which values exist, so the type, the
// stored-value check and the Account page's picker cannot drift apart -
// the check used to be a hand-written `stored === "green" || stored ===
// "blue"`, which needs remembering on every addition and silently falls
// back to orange when it is forgotten.
//
// Orange is the default and therefore has no override block in
// styles.css; every other value does. The server's own enum
// (auth/routes.ts) and the users.pref_accent_color CHECK constraint are
// the two copies outside this file that have to move with it.
export const ACCENT_COLORS = ["orange", "green", "blue", "lila", "pink", "evening"] as const;

export type AccentColor = (typeof ACCENT_COLORS)[number];

const ACCENT_KEY = "porttorch.accent";

// Anything unrecognised reads as the default rather than being applied -
// a value can outlive its own CSS (a browser that stored an accent this
// build no longer ships), and an unknown data-accent would silently mean
// "orange" anyway, just with the attribute left wrong.
export function parseAccent(value: string | null): AccentColor {
  return (ACCENT_COLORS as readonly string[]).includes(value ?? "") ? (value as AccentColor) : "orange";
}

export function getStoredAccent(): AccentColor {
  return parseAccent(localStorage.getItem(ACCENT_KEY));
}

// Distinguishes "this browser has never had an accent choice made on it"
// from "green was explicitly chosen" - getStoredAccent alone can't tell
// those apart (both read as "green"). Used to decide whether the
// account's own accent preference (Account page) should apply on a new
// browser/device, without ever overriding a choice already made on this
// one - same reasoning as lib/theme.ts's hasStoredTheme.
export function hasStoredAccent(): boolean {
  return localStorage.getItem(ACCENT_KEY) !== null;
}

export function applyAccent(accent: AccentColor): void {
  document.documentElement.setAttribute("data-accent", accent);
  localStorage.setItem(ACCENT_KEY, accent);
}
