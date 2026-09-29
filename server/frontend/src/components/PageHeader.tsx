import { Link, NavLink } from "react-router";
import { api, Me } from "../api";
import Brand from "./Brand";
import { IconLogOut, IconSearch } from "./icons";
import NavGroup from "./NavGroup";
import ThemeToggle from "./ThemeToggle";
import { navEntries } from "../lib/navigation";
import { openQuickSearch, quickSearchShortcut } from "../lib/quickSearch";

export default function PageHeader({ me, onLogout }: { me: Me; onLogout: () => void }) {
  return (
    <>
      <header>
        <h1>
          <Brand />
        </h1>
        <div className="user-bar">
          <button
            className="quicksearch-trigger"
            onClick={openQuickSearch}
            title="Search hosts, CVEs and pages"
            aria-label="Search"
            aria-keyshortcuts="Control+K Meta+K"
          >
            <IconSearch /> <span className="quicksearch-trigger-label">Search</span> <kbd>{quickSearchShortcut()}</kbd>
          </button>
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
        {navEntries(me.role).map((entry) =>
          entry.kind === "link" ? (
            <NavLink key={entry.item.to} to={entry.item.to} end={entry.item.to === "/"}>
              {entry.item.label}
            </NavLink>
          ) : (
            <NavGroup key={entry.label} label={entry.label} items={entry.items.map(({ to, label }) => ({ to, label }))} />
          )
        )}
      </nav>
    </>
  );
}
