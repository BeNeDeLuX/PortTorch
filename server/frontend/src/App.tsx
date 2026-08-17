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
import NucleiProfiles from "./pages/NucleiProfiles";
import NucleiFindings from "./pages/NucleiFindings";
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

  // Every route except /login and /account (the escape valve someone
  // with totpSetupRequired needs to reach) goes through this - the
  // not-logged-in and admin-only checks already existed per-route as a
  // repeated ternary; this just adds one more condition, checked first,
  // in one place instead of duplicating it across every route below. A
  // requireAdmin route redirects to "/" as before when the role check
  // fails, but to "/account" when totpSetupRequired is the reason - that
  // condition alone already implies role === "admin", so ordering the
  // checks this way (2FA before role) is never actually ambiguous.
  function routeElement(requireAdmin: boolean, render: (me: Me) => React.ReactElement): React.ReactElement {
    if (!me) return <Navigate to="/login" replace />;
    if (me.totpSetupRequired) return <Navigate to="/account" replace />;
    if (requireAdmin && me.role !== "admin") return <Navigate to="/" replace />;
    return render(me);
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
        element={routeElement(false, (m) => <Dashboard me={m} onLogout={() => setMe(null)} />)}
      />
      <Route
        path="/account"
        element={
          me ? (
            <Account me={me} onLogout={() => setMe(null)} onMeRefresh={() => api.me().then(handleMe)} />
          ) : (
            <Navigate to="/login" replace />
          )
        }
      />
      <Route
        path="/hosts/:id"
        element={routeElement(false, (m) => <HostDetail me={m} onLogout={() => setMe(null)} />)}
      />
      <Route
        path="/agents"
        element={routeElement(false, (m) => <ScannerAgents me={m} onLogout={() => setMe(null)} />)}
      />
      <Route
        path="/schedules"
        element={routeElement(false, (m) => <Schedules me={m} onLogout={() => setMe(null)} />)}
      />
      <Route
        path="/scan-history"
        element={routeElement(false, (m) => <ScanHistory me={m} onLogout={() => setMe(null)} />)}
      />
      <Route
        path="/certificates"
        element={routeElement(false, (m) => <Certificates me={m} onLogout={() => setMe(null)} />)}
      />
      <Route
        path="/vulnerabilities"
        element={routeElement(false, (m) => <Vulnerabilities me={m} onLogout={() => setMe(null)} />)}
      />
      <Route path="/users" element={routeElement(true, (m) => <Users me={m} onLogout={() => setMe(null)} />)} />
      <Route
        path="/digest"
        element={routeElement(false, (m) => <Digest me={m} onLogout={() => setMe(null)} />)}
      />
      <Route
        path="/trends"
        element={routeElement(false, (m) => <Trends me={m} onLogout={() => setMe(null)} />)}
      />
      <Route
        path="/webhooks"
        element={routeElement(false, (m) => <Webhooks me={m} onLogout={() => setMe(null)} />)}
      />
      <Route path="/audit" element={routeElement(true, (m) => <Audit me={m} onLogout={() => setMe(null)} />)} />
      <Route
        path="/excludes"
        element={routeElement(true, (m) => <Excludes me={m} onLogout={() => setMe(null)} />)}
      />
      <Route
        path="/api-tokens"
        element={routeElement(true, (m) => <ApiTokens me={m} onLogout={() => setMe(null)} />)}
      />
      <Route
        path="/scan-profiles"
        element={routeElement(true, (m) => <ScanProfiles me={m} onLogout={() => setMe(null)} />)}
      />
      <Route
        path="/nuclei-profiles"
        element={routeElement(true, (m) => <NucleiProfiles me={m} onLogout={() => setMe(null)} />)}
      />
      <Route
        path="/nuclei-findings"
        element={routeElement(false, (m) => <NucleiFindings me={m} onLogout={() => setMe(null)} />)}
      />
      <Route
        path="/health"
        element={routeElement(false, (m) => <FleetHealth me={m} onLogout={() => setMe(null)} />)}
      />
      <Route
        path="/settings"
        element={routeElement(true, (m) => <Settings me={m} onLogout={() => setMe(null)} />)}
      />
      </Routes>
    </>
  );
}
