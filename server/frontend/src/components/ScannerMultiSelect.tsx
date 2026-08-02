import { useEffect, useRef, useState } from "react";

// Minimal shape rather than the full ScannerAgent - callers that need a
// synthetic, non-agent option in the list (e.g. Excludes.tsx's "global,
// no specific scanner" filter entry) can pass one in without fabricating
// unrelated ScannerAgent fields just to satisfy the type.
export interface ScannerMultiSelectOption {
  id: string;
  name: string;
}

// Closed-by-default dropdown that lets multiple scanner agents be picked
// at once - a plain <select multiple> renders as an always-open listbox,
// not a compact dropdown, so this is a small custom one instead (button +
// an absolutely-positioned checkbox panel, closing on an outside click).
// Empty selection means "no restriction" everywhere this is used (the
// dashboard's Scanner filter, and the Users page's per-account scanner
// access), so there's no separate "All" option - it's just what having
// nothing checked already means.
export default function ScannerMultiSelect({
  agents,
  selectedIds,
  onChange,
  emptyLabel = "All Scanner",
  align = "left",
}: {
  agents: ScannerMultiSelectOption[];
  selectedIds: string[];
  onChange: (ids: string[]) => void;
  emptyLabel?: string;
  // "left" (the panel's left edge lines up with the toggle, growing
  // rightward) suits a toggle sitting on the left of its row; "right"
  // suits one pushed to the right (e.g. via .push-right) so the panel
  // grows leftward instead of overflowing past the viewport's edge.
  align?: "left" | "right";
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

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

  function toggle(id: string) {
    onChange(selectedIds.includes(id) ? selectedIds.filter((i) => i !== id) : [...selectedIds, id]);
  }

  const label =
    selectedIds.length === 0
      ? emptyLabel
      : selectedIds.length === 1
        ? agents.find((a) => a.id === selectedIds[0])?.name ?? "1 scanner"
        : `${selectedIds.length} scanners`;

  return (
    <div className="scanner-multiselect" ref={ref}>
      <button type="button" className="scanner-multiselect-toggle" onClick={() => setOpen((o) => !o)}>
        {label}
        <span className="scanner-multiselect-caret">▾</span>
      </button>
      {open && (
        <div className={`scanner-multiselect-panel${align === "right" ? " scanner-multiselect-panel-right" : ""}`}>
          {agents.length === 0 ? (
            <p className="empty">No scanner agents.</p>
          ) : (
            agents.map((a) => (
              <label key={a.id}>
                <input type="checkbox" checked={selectedIds.includes(a.id)} onChange={() => toggle(a.id)} />
                {a.name}
              </label>
            ))
          )}
        </div>
      )}
    </div>
  );
}
