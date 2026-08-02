import { FormEvent, useState } from "react";
import { api, Me } from "../api";
import ThemeToggle from "../components/ThemeToggle";

export default function Login({ onLogin }: { onLogin: (me: Me) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [awaitingTotp, setAwaitingTotp] = useState(false);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handlePasswordSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const result = await api.login(username, password);
      if ("requiresTotp" in result) {
        setAwaitingTotp(true);
      } else {
        onLogin(result);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleTotpSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const me = await api.verifyTotp(code.trim());
      onLogin(me);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid code");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-theme-toggle">
        <ThemeToggle />
      </div>
      <img src="/porttorch-logo-transparent.svg" alt="PortTorch" className="login-logo login-logo-dark" />
      <img src="/porttorch-logo-light.svg" alt="PortTorch" className="login-logo login-logo-light" />
      {!awaitingTotp ? (
        <form className="login-card" onSubmit={handlePasswordSubmit}>
          <label>
            Username
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
          </label>
          <label>
            Password
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          {error && <p className="error">{error}</p>}
          <button type="submit" disabled={submitting}>
            {submitting ? "..." : "Log in"}
          </button>
        </form>
      ) : (
        <form className="login-card" onSubmit={handleTotpSubmit}>
          <label>
            Authenticator code
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoFocus
              autoComplete="one-time-code"
              inputMode="numeric"
              placeholder="6-digit code, or a recovery code"
            />
          </label>
          {error && <p className="error">{error}</p>}
          <button type="submit" disabled={submitting}>
            {submitting ? "..." : "Verify"}
          </button>
          <button
            type="button"
            className="link-button"
            onClick={() => {
              setAwaitingTotp(false);
              setCode("");
              setError(null);
            }}
          >
            back to login
          </button>
        </form>
      )}
    </div>
  );
}
