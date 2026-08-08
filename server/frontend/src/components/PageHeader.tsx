import { Link, NavLink } from "react-router";
import { api, Me } from "../api";
import Brand from "./Brand";
import ThemeToggle from "./ThemeToggle";

export default function PageHeader({
  me,
  onLogout,
  linkHome = true,
}: {
  me: Me;
  onLogout: () => void;
  linkHome?: boolean;
}) {
  return (
    <>
      <header>
        <h1>{linkHome ? <Link to="/"><Brand /></Link> : <Brand />}</h1>
        <div className="user-bar">
          <ThemeToggle />
          <Link to="/account">
            {me.username} ({me.role})
          </Link>
          <button
            onClick={async () => {
              await api.logout();
              onLogout();
            }}
          >
            Logout
          </button>
        </div>
      </header>

      <nav className="main-nav">
        <NavLink to="/" end>Scan Results</NavLink>
        <NavLink to="/agents">Scanner Agents</NavLink>
        <NavLink to="/schedules">Schedule Scans</NavLink>
        <NavLink to="/scan-history">Scan History</NavLink>
        <NavLink to="/certificates">Certificates</NavLink>
        <NavLink to="/vulnerabilities">Vulnerabilities</NavLink>
        <NavLink to="/digest">Digest</NavLink>
        <NavLink to="/trends">Trends</NavLink>
        <NavLink to="/webhooks">Webhooks</NavLink>
        {me.role === "admin" && <NavLink to="/users">Users</NavLink>}
        {me.role === "admin" && <NavLink to="/audit">Audit</NavLink>}
        {me.role === "admin" && <NavLink to="/excludes">Excludes</NavLink>}
        {me.role === "admin" && <NavLink to="/api-tokens">API Tokens</NavLink>}
      </nav>
    </>
  );
}
