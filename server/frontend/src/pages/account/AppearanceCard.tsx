import { FormEvent, useEffect, useState } from "react";
import { Me, UserPreferences, api } from "../../api";
import { IconSave } from "../../components/icons";
import SettingsCard, { SaveState } from "../../components/SettingsCard";
import { AccentColor, applyAccent } from "../../lib/accent";
import { LayoutWidth, applyLayoutWidth } from "../../lib/layoutWidth";
import { applyTheme } from "../../lib/theme";

export default function AppearanceCard({ me, onSaved }: { me: Me; onSaved: (p: UserPreferences) => void }) {
  const [theme, setTheme] = useState(me.preferences.theme ?? "");
  const [accent, setAccent] = useState(me.preferences.accentColor ?? "");
  const [layout, setLayout] = useState(me.preferences.layoutWidth ?? "");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  // Re-sync from the object the shell holds, so a save in a neighbouring
  // card cannot leave this one showing a stale copy behind its own dirty
  // marker - the same effect every settings card runs for that reason.
  useEffect(() => {
    setTheme(me.preferences.theme ?? "");
    setAccent(me.preferences.accentColor ?? "");
    setLayout(me.preferences.layoutWidth ?? "");
  }, [me.preferences.theme, me.preferences.accentColor, me.preferences.layoutWidth]);

  const dirty =
    theme !== (me.preferences.theme ?? "") ||
    accent !== (me.preferences.accentColor ?? "") ||
    layout !== (me.preferences.layoutWidth ?? "");

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setSaved(false);
    const nextTheme = theme ? (theme as "dark" | "light") : null;
    const nextAccent = accent ? (accent as AccentColor) : null;
    const nextLayout = layout ? (layout as LayoutWidth) : null;
    try {
      // Only this card's two fields are sent. PATCH /auth/preferences
      // decides per field on `"field" in body`, so everything else keeps
      // whatever it had - which is what lets these cards save
      // independently rather than each re-submitting the whole set.
      const updated = await api.updatePreferences({
        theme: nextTheme,
        accentColor: nextAccent,
        layoutWidth: nextLayout,
      });
      // Applies to this browser immediately, same as the header's quick
      // toggle - but only for a concrete choice. "Browser default" does
      // not change what is active now; it only stops seeding a theme for
      // a browser that has never had one chosen.
      if (nextTheme) applyTheme(nextTheme);
      // Accent has no "browser default" - "" is the explicit orange - so
      // it always applies rather than being a no-op sentinel.
      applyAccent(nextAccent ?? "orange");
      // Same as accent: no "browser default" sentinel, so it always
      // applies here and now. The stored account value only decides what
      // a browser that has never been told gets seeded with.
      applyLayoutWidth(nextLayout ?? "standard");
      onSaved(updated);
      setSaved(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <SettingsCard
      title="Appearance"
      description="How the dashboard looks for you, on every browser you sign in from."
      error={error}
    >
      <form className="settings-form" onSubmit={save}>
        <label>
          Theme
          <select value={theme} onChange={(e) => setTheme(e.target.value)} disabled={busy}>
            <option value="">Browser default</option>
            <option value="dark">Dark</option>
            <option value="light">Light</option>
          </select>
        </label>
        <label>
          Accent color
          <select value={accent} onChange={(e) => setAccent(e.target.value)} disabled={busy}>
            <option value="">Orange (default)</option>
            <option value="green">Green</option>
            <option value="blue">Blue</option>
            <option value="lila">Lila</option>
            <option value="pink">Pink</option>
            {/* Vim's own colorscheme, named after it rather than after
                the hue, since that is what someone picking it is asking
                for - see styles.css for where the value comes from. */}
            <option value="evening">Evening (Vim)</option>
          </select>
        </label>
        <label>
          Layout width
          <select value={layout} onChange={(e) => setLayout(e.target.value)} disabled={busy}>
            <option value="">Standard (up to 1600px)</option>
            <option value="wide">Wide (use the full screen)</option>
          </select>
        </label>
        {/* Same "empty"-styled note the scan forms use for a field that
            needs a sentence rather than a label - the per-browser part
            is the half people would otherwise be surprised by. */}
        <p className="empty">
          Wide drops the page's width cap, for a 32" or ultrawide monitor where the standard layout leaves
          most of the screen empty. Like the theme, it is remembered per browser - a laptop you also sign in
          from keeps its own setting, and this choice only seeds a browser that has never had one.
        </p>
        <div className="inline-actions settings-form-actions">
          <button type="submit" className="btn-icon-label" disabled={busy || !dirty}>
            <IconSave /> {busy ? "Saving..." : "Save"}
          </button>
          <SaveState saved={saved} dirty={dirty} />
        </div>
      </form>
    </SettingsCard>
  );
}
