// How wide the page is allowed to get, mirroring lib/accent.ts exactly
// (data-layout attribute + localStorage, applied before first paint in
// main.tsx). One CSS custom property (--layout-max-width in styles.css)
// is where both page wrappers - .dashboard and .host-detail - take their
// cap from.
//
// Per browser rather than only per account, and that is the point: a
// screen is a property of the workstation, not of the person. The same
// analyst can sit at a 32" curved monitor at work and a 13" laptop at
// home, and one stored answer cannot be right for both. The account
// preference seeds a browser that has never had a choice made on it, the
// same rule theme already follows.
export const LAYOUT_WIDTHS = ["standard", "wide"] as const;

export type LayoutWidth = (typeof LAYOUT_WIDTHS)[number];

const LAYOUT_KEY = "porttorch.layoutWidth";

// Anything unrecognised reads as the default, so a value that outlives
// its own CSS degrades to the layout every build knows how to render.
export function parseLayoutWidth(value: string | null): LayoutWidth {
  return (LAYOUT_WIDTHS as readonly string[]).includes(value ?? "") ? (value as LayoutWidth) : "standard";
}

export function getStoredLayoutWidth(): LayoutWidth {
  return parseLayoutWidth(localStorage.getItem(LAYOUT_KEY));
}

// "this browser has never been told" vs. "standard was chosen here" -
// only the first may be seeded from the account preference. Same
// reasoning as hasStoredTheme/hasStoredAccent.
export function hasStoredLayoutWidth(): boolean {
  return localStorage.getItem(LAYOUT_KEY) !== null;
}

export function applyLayoutWidth(width: LayoutWidth): void {
  document.documentElement.setAttribute("data-layout", width);
  localStorage.setItem(LAYOUT_KEY, width);
}
