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
            { to: "/agents", label: "Scanner Agents" },
            { to: "/schedules", label: "Schedule Scans" },
            { to: "/scan-history", label: "Scan History" },
            ...(me.role === "admin" ? [{ to: "/scan-profiles", label: "Scan Profiles" }] : []),
          ]}
        />
        <NavGroup
          label="Insights"
          items={[
            { to: "/certificates", label: "Certificates" },
            { to: "/vulnerabilities", label: "Vulnerabilities" },
            { to: "/digest", label: "Digest" },
            { to: "/trends", label: "Trends" },
          ]}
        />
        {me.role === "admin" && (
          <NavGroup
            label="Admin"
            items={[
              { to: "/webhooks", label: "Webhooks" },
              { to: "/users", label: "Users" },
              { to: "/audit", label: "Audit" },
              { to: "/excludes", label: "Excludes" },
              { to: "/api-tokens", label: "API Tokens" },
              { to: "/settings", label: "Settings" },
            ]}
          />
        )}
      </nav>
    </>
  );
}
