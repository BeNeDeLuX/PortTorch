export type Theme = "dark" | "light";

const THEME_KEY = "porttorch.theme";

export function getStoredTheme(): Theme {
  return localStorage.getItem(THEME_KEY) === "light" ? "light" : "dark";
}

// Distinguishes "this browser has never had a theme choice made on it"
// from "dark was explicitly chosen" - getStoredTheme alone can't tell
// those apart (both read as "dark"). Used to decide whether the
// account's own default theme preference (Account page) should apply on
// a new browser/device, without ever overriding a choice already made
// via the quick toggle on this one.
export function hasStoredTheme(): boolean {
  return localStorage.getItem(THEME_KEY) !== null;
}

export function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem(THEME_KEY, theme);
}
