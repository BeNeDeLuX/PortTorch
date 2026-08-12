import { FormEvent, useEffect, useState } from "react";
import { api, DashboardUser, Me, ScannerAgent } from "../api";
import { IconEdit, IconPlus, IconRefresh, IconSave, IconTrash, IconX } from "../components/icons";
import PageHeader from "../components/PageHeader";
import ScannerMultiSelect from "../components/ScannerMultiSelect";
import { formatDateTime } from "../lib/formatDate";

function scannerAccessLabel(scannerAgentIds: string[], agents: ScannerAgent[]): string {
  if (scannerAgentIds.length === 0) return "All";
  const byId = new Map(agents.map((a) => [a.id, a.name]));
  return scannerAgentIds.map((id) => byId.get(id) ?? id).join(", ");
}

export default function Users({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [users, setUsers] = useState<DashboardUser[]>([]);
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("user");
  const [scannerAgentIds, setScannerAgentIds] = useState<string[]>([]);
  const [editingUserId, setEditingUserId] = useState<number | null>(null);
  const [editScannerAgentIds, setEditScannerAgentIds] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      const [u, a] = await Promise.all([api.users(), api.agents()]);
      setUsers(u);
      setAgents(a);
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!username.trim() || !password) return;
    setError(null);
    try {
      await api.createUser({ username: username.trim(), password, role, scannerAgentIds });
      setUsername("");
      setPassword("");
      setRole("user");
      setScannerAgentIds([]);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create user");
    }
  }

  async function handleDelete(u: DashboardUser) {
    if (!window.confirm(`Delete user "${u.username}"?`)) return;
    setError(null);
    try {
      await api.deleteUser(u.id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete user");
    }
  }

  async function handleResetTwoFactor(u: DashboardUser) {
    if (
      !window.confirm(
        `Reset 2FA for "${u.username}"? This turns it off - they'll need to set it up again from their Account page.`
      )
    ) {
      return;
    }
    setError(null);
    try {
      await api.resetUserTwoFactor(u.id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to reset 2FA");
    }
  }

  function startEditAccess(u: DashboardUser) {
    setEditingUserId(u.id);
    setEditScannerAgentIds(u.scannerAgentIds);
  }

  async function handleSaveAccess(u: DashboardUser) {
    setError(null);
    try {
      await api.setUserScannerAgents(u.id, editScannerAgentIds);
      setEditingUserId(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update scanner access");
    }
  }

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Dashboard Users</h2>

      {error && <p className="error">{error}</p>}

      <form className="schedule-form" onSubmit={handleCreate}>
        <input placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
        <input
          type="password"
          placeholder="Password (min. 8 characters)"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <select
          value={role}
          onChange={(e) => {
            setRole(e.target.value);
            if (e.target.value === "admin") setScannerAgentIds([]);
          }}
        >
          <option value="user">user (read-only)</option>
          <option value="operator">operator (read-only + rescan)</option>
          <option value="admin">admin</option>
        </select>
        {role !== "admin" && agents.length > 0 && (
          <label className="date-range-filter">
            Scanner access
            <ScannerMultiSelect agents={agents} selectedIds={scannerAgentIds} onChange={setScannerAgentIds} />
          </label>
        )}
        <button type="submit" className="btn-icon-label">
          <IconPlus /> Create
        </button>
      </form>

      {loading ? (
        <p>Loading...</p>
      ) : users.length === 0 ? (
        <p className="empty">No users found.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Role</th>
              <th>Scanner access</th>
              <th>Created</th>
              <th>Last login</th>
              <th>2FA</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.username}</td>
                <td>{u.role}</td>
                <td>
                  {u.role !== "admin" && editingUserId === u.id ? (
                    <div className="actions-cell">
                      <ScannerMultiSelect agents={agents} selectedIds={editScannerAgentIds} onChange={setEditScannerAgentIds} />
                      <button className="btn-icon-label" onClick={() => handleSaveAccess(u)}>
                        <IconSave /> Save
                      </button>
                      <button className="btn-icon-label" onClick={() => setEditingUserId(null)}>
                        <IconX /> Cancel
                      </button>
                    </div>
                  ) : (
                    scannerAccessLabel(u.scannerAgentIds, agents)
                  )}
                </td>
                <td>{formatDateTime(u.created_at, me.preferences)}</td>
                <td>{u.last_login_at ? formatDateTime(u.last_login_at, me.preferences) : "never"}</td>
                <td>{u.totp_enabled ? "enabled" : "disabled"}</td>
                <td>
                  <div className="actions-cell">
                    {u.role !== "admin" && editingUserId !== u.id && (
                      <button className="btn-icon-label" onClick={() => startEditAccess(u)}>
                        <IconEdit /> Edit access
                      </button>
                    )}
                    {u.totp_enabled && (
                      <button className="btn-icon-label" onClick={() => handleResetTwoFactor(u)}>
                        <IconRefresh /> Reset 2FA
                      </button>
                    )}
                    {u.username !== me.username && (
                      <button className="btn-icon-label" onClick={() => handleDelete(u)}>
                        <IconTrash /> Delete
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
