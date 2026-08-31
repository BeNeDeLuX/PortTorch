import { Link, NavLink } from "react-router";
import { api, Me } from "../api";
import Brand from "./Brand";
import { IconLogOut } from "./icons";
import NavGroup from "./NavGroup";
import ThemeToggle from "./ThemeToggle";

export default function PageHeader({ me, onLogout }: { me: Me; onLogout: () => void }) {
  return (
    <>
      <header>
        <h1>
          <Brand />
        </h1>
        <div className="user-bar">
          <ThemeToggle />
          <Link to="/account">
            {me.username} ({me.role})
          </Link>
          <button
            className="btn-icon-label"
            onClick={async () => {
              await api.logout();
              onLogout();
            }}
          >
            <IconLogOut /> Logout
          </button>
        </div>
      </header>

      <nav className="main-nav">
        <NavLink to="/" end>Scan Results</NavLink>
        <NavGroup
          label="Scanning"
          items={[
            { to: "/adhoc-scans", label: "Ad-hoc Scans" },
            { to: "/schedules", label: "Schedule Scans" },
            { to: "/agents", label: "Scanner Agents" },
            { to: "/scan-history", label: "Scan History" },
            { to: "/networks", label: "Network Coverage" },
            ...(me.role === "admin"
              ? [
                  { to: "/scan-profiles", label: "Scan Profiles" },
                  { to: "/nuclei-profiles", label: "Nuclei Profiles" },
                  { to: "/excludes", label: "Excludes" },
                ]
              : []),
          ]}
        />
        <NavLink to="/certificates">Certificates</NavLink>
        <NavLink to="/ssh-keys">SSH Keys</NavLink>
        <NavLink to="/vulnerabilities">Vulnerabilities</NavLink>
        <NavLink to="/web-findings">Web Findings</NavLink>
        <NavLink to="/digest">Digest</NavLink>
        <NavLink to="/trends">Trends</NavLink>
        <NavLink to="/health">Health</NavLink>
        {me.role === "admin" && (
          <NavGroup
            label="Admin"
            items={[
              { to: "/webhooks", label: "Webhooks" },
              { to: "/users", label: "Users" },
              { to: "/audit", label: "Audit" },
              { to: "/api-tokens", label: "API Tokens" },
              { to: "/settings", label: "Settings" },
            ]}
          />
        )}
      </nav>
    </>
  );
}
