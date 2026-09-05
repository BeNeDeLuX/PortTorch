import { useState } from "react";
import { api, StorageUsage } from "../../api";
import { IconRefresh } from "../../components/icons";
import { formatBytes } from "../../lib/formatBytes";
import SettingsCard from "./SettingsCard";

export default function StorageCard() {
  const [storage, setStorage] = useState<StorageUsage | null>(null);
  const [loading, setLoading] = useState(false);

  // On demand, not on page load: the screenshot figure is a real
  // directory scan, and a fleet with tens of thousands of captures
  // shouldn't pay for it every time someone opens Settings for an
  // unrelated reason.
  async function load() {
    setLoading(true);
    try {
      setStorage(await api.storageUsage());
    } catch {
      setStorage(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <SettingsCard
      title="Storage"
      description={
        <>
          Where the database is actually going. The tables listed are append-only - rows are only reclaimed when their
          host ages out of the retention window. Screenshot files are counted from disk rather than the database, so
          noticeably more files than rows means captures left behind by deletes that didn't remove them.
        </>
      }
    >
      <div className="inline-actions">
        <button className="btn-icon-label" onClick={load} disabled={loading}>
          <IconRefresh /> {loading ? "Measuring..." : storage ? "Refresh" : "Show storage usage"}
        </button>
      </div>
      {storage && (
        <div className="table-scroll settings-table">
          <table className="storage-table">
            <thead>
              <tr>
                <th>Table</th>
                <th>Rows</th>
                <th>Size</th>
              </tr>
            </thead>
            <tbody>
              {storage.tables.map((t) => (
                <tr key={t.table}>
                  <td>{t.table}</td>
                  <td>{t.rows.toLocaleString()}</td>
                  <td>{formatBytes(t.bytes)}</td>
                </tr>
              ))}
              <tr>
                <td>screenshot files on disk</td>
                <td>{storage.screenshots.files.toLocaleString()}</td>
                <td>{formatBytes(storage.screenshots.bytes)}</td>
              </tr>
              <tr>
                <td>
                  <strong>database total</strong>
                </td>
                <td>-</td>
                <td>
                  <strong>{formatBytes(storage.databaseBytes)}</strong>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      )}
    </SettingsCard>
  );
}
