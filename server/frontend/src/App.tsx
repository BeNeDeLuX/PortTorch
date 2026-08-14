import { useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router";
import { api, Me } from "./api";
import { applyTheme, hasStoredTheme } from "./lib/theme";
import { applyAccent, hasStoredAccent } from "./lib/accent";
import Login from "./pages/Login";
import Account from "./pages/Account";
import Dashboard from "./pages/Dashboard";
import HostDetail from "./pages/HostDetail";
import ScannerAgents from "./pages/ScannerAgents";
import ScanHistory from "./pages/ScanHistory";
import Schedules from "./pages/Schedules";
import Certificates from "./pages/Certificates";
import Vulnerabilities from "./pages/Vulnerabilities";
import Users from "./pages/Users";
import Digest from "./pages/Digest";
import Trends from "./pages/Trends";
import Webhooks from "./pages/Webhooks";
import Audit from "./pages/Audit";
import Excludes from "./pages/Excludes";
import ApiTokens from "./pages/ApiTokens";
import ScanProfiles from "./pages/ScanProfiles";
import Settings from "./pages/Settings";
import FleetHealth from "./pages/FleetHealth";

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  // The account's own default theme (set on the Account page) only ever
  // applies on a browser that's never had an explicit choice made on it
  // (main.tsx already applies the local one, synchronously, before first
  // paint, to avoid a flash) - it can seed a new browser/device, but can
  // never silently override the quick toggle on one already in use.
  function handleMe(result: Me) {
    setMe(result);
    if (!hasStoredTheme() && result.preferences.theme) {
      applyTheme(result.preferences.theme);
    }
    if (!hasStoredAccent() && result.preferences.accentColor) {
      applyAccent(result.preferences.accentColor);
    }
  }

  useEffect(() => {
    api
      .me()
      .then(handleMe)
      .catch(() => setMe(null))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return null;
  }

  return (
    <>
      {me && <div className="version-badge">v{me.version}</div>}
      <Routes>
      <Route
        path="/login"
        element={me ? <Navigate to="/" replace /> : <Login onLogin={handleMe} />}
      />
      <Route
        path="/"
        element={me ? <Dashboard me={me} onLogout={() => setMe(null)} /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/account"
        element={me ? <Account me={me} onLogout={() => setMe(null)} /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/hosts/:id"
        element={me ? <HostDetail me={me} onLogout={() => setMe(null)} /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/agents"
        element={me ? <ScannerAgents me={me} onLogout={() => setMe(null)} /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/schedules"
        element={me ? <Schedules me={me} onLogout={() => setMe(null)} /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/scan-history"
        element={me ? <ScanHistory me={me} onLogout={() => setMe(null)} /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/certificates"
        element={me ? <Certificates me={me} onLogout={() => setMe(null)} /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/vulnerabilities"
        element={me ? <Vulnerabilities me={me} onLogout={() => setMe(null)} /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/users"
        element={
          me && me.role === "admin" ? <Users me={me} onLogout={() => setMe(null)} /> : <Navigate to="/" replace />
        }
      />
      <Route
        path="/digest"
        element={me ? <Digest me={me} onLogout={() => setMe(null)} /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/trends"
        element={me ? <Trends me={me} onLogout={() => setMe(null)} /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/webhooks"
        element={me ? <Webhooks me={me} onLogout={() => setMe(null)} /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/audit"
        element={
          me && me.role === "admin" ? <Audit me={me} onLogout={() => setMe(null)} /> : <Navigate to="/" replace />
        }
      />
      <Route
        path="/excludes"
        element={
          me && me.role === "admin" ? <Excludes me={me} onLogout={() => setMe(null)} /> : <Navigate to="/" replace />
        }
      />
      <Route
        path="/api-tokens"
        element={
          me && me.role === "admin" ? <ApiTokens me={me} onLogout={() => setMe(null)} /> : <Navigate to="/" replace />
        }
      />
      <Route
        path="/scan-profiles"
        element={
          me && me.role === "admin" ? <ScanProfiles me={me} onLogout={() => setMe(null)} /> : <Navigate to="/" replace />
        }
      />
      <Route
        path="/health"
        element={me ? <FleetHealth me={me} onLogout={() => setMe(null)} /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/settings"
        element={
          me && me.role === "admin" ? <Settings me={me} onLogout={() => setMe(null)} /> : <Navigate to="/" replace />
        }
      />
      </Routes>
    </>
  );
}
