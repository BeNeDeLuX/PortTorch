// Small, hand-drawn inline icons - no icon library dependency, matching
// this app's existing zero-UI-dependency approach (even the Trends charts
// are plain inline SVG, see pages/Trends.tsx). stroke="currentColor" so
// each icon inherits whatever color/theme the surrounding text already
// has, with no separate light/dark handling needed. aria-hidden since
// every current usage sits next to a visible text label.

function iconProps(size: number) {
  return {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none" as const,
    stroke: "currentColor",
    strokeWidth: 2,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
  };
}

export function IconRefresh({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <polyline points="23 4 23 10 17 10" />
      <polyline points="1 20 1 14 7 14" />
      <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
    </svg>
  );
}

export function IconDownload({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  );
}

export function IconSearch({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
}

// A saved search is a named, reusable filter preset (see CLAUDE.md's
// "Saved searches" section) - a bookmark reads as "keep this for later"
// more specifically than a generic floppy-disk save icon would.
export function IconBookmark({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z" />
    </svg>
  );
}

export function IconLogOut({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <polyline points="16 17 21 12 16 7" />
      <line x1="21" y1="12" x2="9" y2="12" />
    </svg>
  );
}
