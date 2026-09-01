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
  // Closing on mouseleave is delayed slightly rather than instant - the
  // panel sits a few pixels below the toggle (see .nav-group-panel's
  // "top: calc(100% + 0.6rem)" in styles.css), and moving the mouse
  // diagonally from toggle to panel briefly crosses that gap, which
  // would otherwise register as leaving .nav-group and close the panel
  // before the pointer ever reaches it.
  const closeTimer = useRef<number | null>(null);
  // Whether the panel currently open was opened by the pointer arriving
  // rather than by a click. Without this, hovering opens the panel and
  // the very next click on the same button closes it again - so anyone
  // who clicks rather than hovers sees it flash and vanish, and on a
  // touch device, where the browser synthesises mouseenter before the
  // click, that is *every* tap.
  const openedByHover = useRef(false);
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
        openedByHover.current = false;
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
    openedByHover.current = false;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);

  // Cancel any pending close if the component unmounts mid-delay (e.g.
  // navigating away right as the mouse leaves) - avoids a setState call
  // on an unmounted component.
  useEffect(() => {
    return () => {
      if (closeTimer.current !== null) window.clearTimeout(closeTimer.current);
    };
  }, []);

  function openNow() {
    if (closeTimer.current !== null) {
      window.clearTimeout(closeTimer.current);
      closeTimer.current = null;
    }
    if (!open) openedByHover.current = true;
    setOpen(true);
  }

  function closeSoon() {
    closeTimer.current = window.setTimeout(() => {
      setOpen(false);
      openedByHover.current = false;
      closeTimer.current = null;
    }, 150);
  }

  // A click on a panel the pointer already opened *pins* it open rather
  // than closing it - which is what someone clicking the button means.
  // The second click, on a panel that is now click-owned, closes it.
  //
  // Reads `open` from the render closure rather than using a functional
  // updater, deliberately: the decision also flips a ref, and React may
  // call an updater twice (StrictMode), which would run that flip twice
  // and turn the second pass into the opposite decision. An event handler
  // sees a current enough `open` for this.
  function toggleFromClick() {
    if (open && openedByHover.current) {
      openedByHover.current = false;
      return;
    }
    openedByHover.current = false;
    setOpen(!open);
  }

  return (
    <div className="nav-group" ref={ref} onMouseEnter={openNow} onMouseLeave={closeSoon}>
      <button
        type="button"
        className={`nav-group-toggle${isActive ? " active" : ""}`}
        onClick={toggleFromClick}
      >
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
