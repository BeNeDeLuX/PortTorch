import { ReactNode } from "react";
import { IconCheck } from "../../components/icons";

// One setting, in a card. Every section on the Settings page is one of
// these, so the eleven hand-rolled <h3> + <p className="host-meta">
// pairs the page used to open each section with are now a single shape.
//
// `wide` marks the sections whose form genuinely doesn't fit a 340px
// column - Alerting has six fields, SMTP seven, SIEM seven - and spans
// them across two grid columns instead, where their fields lay out in
// their own inner grid (see .settings-grid-wide in styles.css).
export default function SettingsCard({
  title,
  description,
  error,
  notice,
  children,
}: {
  title: string;
  description: ReactNode;
  error?: string | null;
  notice?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="settings-card">
      <h3 className="settings-card-title">{title}</h3>
      <div className="settings-card-desc">{description}</div>
      {error && <p className="error">{error}</p>}
      {notice}
      {children}
    </section>
  );
}

// Two signals rather than one, unchanged from before the page was split
// up: a transient confirmation right after a successful write, and a
// persistent marker whenever the field no longer matches what's stored,
// so "is what I'm looking at actually applied?" stays answerable rather
// than only being answered for a few seconds.
export function SaveState({ saved, dirty }: { saved: boolean; dirty: boolean }) {
  if (dirty) return <span className="save-state unsaved">unsaved</span>;
  if (saved) {
    return (
      <span className="save-state saved">
        <IconCheck /> Saved
      </span>
    );
  }
  return null;
}
