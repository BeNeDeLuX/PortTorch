import { FormEvent, useState } from "react";
import { api } from "../../api";
import { IconSave } from "../../components/icons";
import SettingsCard from "../../components/SettingsCard";

export default function PasswordCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  async function save(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setDone(false);
    if (next !== repeat) {
      setError("The two new passwords don't match.");
      return;
    }
    setBusy(true);
    try {
      await api.changePassword(current, next);
      setCurrent("");
      setNext("");
      setRepeat("");
      setDone(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to change password");
    } finally {
      setBusy(false);
    }
  }

  return (
    <SettingsCard
      title="Password"
      description="Changing it requires your current one - being signed in is not on its own proof of who is at the keyboard. Every other session signed in as you is ended; this one stays."
      error={error}
      notice={done ? <p className="callout-success">Password changed.</p> : null}
    >
      <form className="settings-form" onSubmit={save}>
        <label>
          Current password
          <input
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            disabled={busy}
          />
        </label>
        <label>
          {/* The policy floor is 12, not the 8 this said for a long time
              after it was raised - a placeholder that understates it just
              gets the save rejected. */}
          New password (at least 12 characters)
          <input
            type="password"
            autoComplete="new-password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            disabled={busy}
          />
        </label>
        <label>
          Repeat new password
          <input
            type="password"
            autoComplete="new-password"
            value={repeat}
            onChange={(e) => setRepeat(e.target.value)}
            disabled={busy}
          />
        </label>
        <div className="inline-actions settings-form-actions">
          <button type="submit" className="btn-icon-label" disabled={busy || !current || !next}>
            <IconSave /> {busy ? "Changing..." : "Change password"}
          </button>
        </div>
      </form>
      <p className="host-meta">
        Length beats symbols: a passphrase of a few words is stronger than a short mangled one. Your own name and
        obvious words like "password" are refused however they are spelled.
      </p>
    </SettingsCard>
  );
}
