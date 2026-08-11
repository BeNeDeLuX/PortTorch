export type AccentColor = "green" | "orange" | "blue";

const ACCENT_KEY = "porttorch.accent";

export function getStoredAccent(): AccentColor {
  const stored = localStorage.getItem(ACCENT_KEY);
  return stored === "green" || stored === "blue" ? stored : "orange";
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
