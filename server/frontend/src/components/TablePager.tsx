import { ReactNode } from "react";

// Paging over a list the page already has in memory. The fleet-wide
// finding pages filter and sort client-side by design, so paging has to
// happen after that - a server-side page would be a page of the wrong
// set. What this fixes is the third cost of a large result, after query
// time and transfer: rendering ten thousand rows at once.
export const FINDINGS_PAGE_SIZE = 200;

export function pageSlice<T>(rows: T[], page: number, size = FINDINGS_PAGE_SIZE): T[] {
  return rows.slice((page - 1) * size, page * size);
}

export default function TablePager({
  page,
  total,
  onPage,
  size = FINDINGS_PAGE_SIZE,
  children,
}: {
  page: number;
  total: number;
  onPage: (page: number) => void;
  size?: number;
  children?: ReactNode;
}) {
  const pages = Math.max(1, Math.ceil(total / size));
  // One page of results needs no controls at all - which is every fleet
  // small enough for this never to have mattered.
  if (total <= size) return <>{children}</>;

  const from = (page - 1) * size + 1;
  const to = Math.min(page * size, total);
  return (
    <div className="table-pager">
      <button type="button" className="btn-icon-label" onClick={() => onPage(page - 1)} disabled={page <= 1}>
        ← Previous
      </button>
      <span className="host-meta">
        {from.toLocaleString()}-{to.toLocaleString()} of {total.toLocaleString()} · page {page} of {pages}
      </span>
      <button type="button" className="btn-icon-label" onClick={() => onPage(page + 1)} disabled={page >= pages}>
        Next →
      </button>
      {children}
    </div>
  );
}
