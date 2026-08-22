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

export function IconWarning({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
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

export function IconRocket({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z" />
      <path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 19 3c0 2.52-.6 6.7-4 9a22.35 22.35 0 0 1-3 2z" />
      <path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0" />
      <path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5" />
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

export function IconUpload({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="17 8 12 3 7 8" />
      <line x1="12" y1="3" x2="12" y2="15" />
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

// Mirrors IconLogOut - arrow pointing *into* the door instead of out of it.
export function IconLogIn({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
      <polyline points="10 17 15 12 10 7" />
      <line x1="15" y1="12" x2="3" y2="12" />
    </svg>
  );
}

// A "go back to the previous step" action (e.g. Login's 2FA screen
// backing out to the password form) - distinct from IconX's "close/cancel
// this dialog" meaning, even though both back out of something.
export function IconArrowLeft({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <line x1="19" y1="12" x2="5" y2="12" />
      <polyline points="12 19 5 12 12 5" />
    </svg>
  );
}

export function IconTrash({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <polyline points="3 6 5 6 21 6" />
      <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
      <line x1="10" y1="11" x2="10" y2="17" />
      <line x1="14" y1="11" x2="14" y2="17" />
    </svg>
  );
}

export function IconPlus({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <line x1="12" y1="5" x2="12" y2="19" />
      <line x1="5" y1="12" x2="19" y2="12" />
    </svg>
  );
}

// Classic floppy-disk glyph - generic "save this form" (Save preferences,
// Save changes, probe hostname's Save, ...), distinct from IconBookmark's
// more specific "keep this named preset for later" meaning.
export function IconSave({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z" />
      <polyline points="17 21 17 13 7 13 7 21" />
      <polyline points="7 3 7 8 15 8" />
    </svg>
  );
}

export function IconX({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}

// The universal "forbidden" glyph - a circle with a diagonal slash
// through it, reading as "revoked/blocked" more specifically than a
// generic X would.
export function IconBan({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <circle cx="12" cy="12" r="9" />
      <line x1="5.5" y1="5.5" x2="18.5" y2="18.5" />
    </svg>
  );
}

// "Test" (a webhook) sends a one-off payload - a paper airplane reads as
// "dispatch this now" more specifically than a generic play/check icon.
export function IconSend({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <line x1="22" y1="2" x2="11" y2="13" />
      <polygon points="22 2 15 22 11 13 2 9 22 2" />
    </svg>
  );
}

export function IconCheck({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

export function IconEdit({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <path d="M11 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5" />
      <path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4z" />
    </svg>
  );
}

// A key, for password reset actions - deliberately not IconRefresh,
// which "Reset 2FA" right next to it already uses; two adjacent buttons
// sharing an icon would read as two spellings of the same action.
export function IconKey({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <circle cx="7.5" cy="15.5" r="4.5" />
      <path d="M10.7 12.3 20 3" />
      <path d="M17 6l2.5 2.5" />
    </svg>
  );
}

export function IconInfo({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <circle cx="12" cy="12" r="9" />
      <line x1="12" y1="11" x2="12" y2="16" />
      <line x1="12" y1="8" x2="12.01" y2="8" />
    </svg>
  );
}

// HostExportModal's PDF option is window.print() (see CLAUDE.md), not a
// generated file to download - a printer icon reflects what actually
// happens, rather than reusing IconDownload for something that isn't one.
export function IconPrinter({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <polyline points="6 9 6 2 18 2 18 9" />
      <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2" />
      <rect x="6" y="14" width="12" height="8" />
    </svg>
  );
}

export function IconPause({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)}>
      <rect x="6" y="4" width="4" height="16" />
      <rect x="14" y="4" width="4" height="16" />
    </svg>
  );
}

// Play/Stop are conventionally solid shapes (every media player ever),
// unlike every other icon here which is just a stroke - overrides fill
// to currentColor for a recognizable, filled triangle/square instead of
// a thin outline that wouldn't read the same way at this size.
export function IconPlay({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)} fill="currentColor" stroke="none">
      <polygon points="6 3 20 12 6 21 6 3" />
    </svg>
  );
}

// A running scan's "Stop" is a distinct action from a form's "Cancel"
// (IconX) - the filled square is the universal media-player stop glyph.
export function IconStop({ size = 15 }: { size?: number }) {
  return (
    <svg {...iconProps(size)} fill="currentColor" stroke="none">
      <rect x="5" y="5" width="14" height="14" rx="1" />
    </svg>
  );
}
