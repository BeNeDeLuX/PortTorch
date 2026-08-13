import { useEffect, useRef, useState } from "react";
import { NavLink, useLocation } from "react-router";

export interface NavGroupItem {
  to: string;
  label: string;
}

// Closed-by-default dropdown for a cluster of related top-nav links -
// same toggle+outside-click mechanics as ScannerMultiSelect.tsx (the
// only other dropdown pattern in this app), swapping the checkbox panel
// for a column of NavLinks. Exists because the top nav (PageHeader.tsx)
// outgrew a single flat row once it reached 14 items - grouping keeps
// the row short regardless of how many items live inside a given group.
export default function NavGroup({ label, items }: { label: string; items: NavGroupItem[] }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const location = useLocation();

  // Mirrors NavLink's own active-match closely enough for this purpose:
  // exact match, or a path-segment boundary (so /scan-history doesn't
  // also light up for a hypothetical /scan-history-extra route) - lets
  // the closed toggle itself show which group the current page lives in.
  const isActive = items.some((item) => location.pathname === item.to || location.pathname.startsWith(item.to + "/"));

  useEffect(() => {
    if (!open) return;
    function handleClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [open]);

  // A click on a NavLink inside the panel lands inside the ref'd
  // container, so the outside-click handler above never fires for it -
  // closing on route change instead covers that (and browser back/
  // forward, and keyboard-driven navigation) in one place.
  useEffect(() => {
    setOpen(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);

  return (
    <div className="nav-group" ref={ref}>
      <button type="button" className={`nav-group-toggle${isActive ? " active" : ""}`} onClick={() => setOpen((o) => !o)}>
        {label}
        <span className="nav-group-caret">▾</span>
      </button>
      {open && (
        <div className="nav-group-panel">
          {items.map((item) => (
            <NavLink key={item.to} to={item.to}>
              {item.label}
            </NavLink>
          ))}
        </div>
      )}
    </div>
  );
}
