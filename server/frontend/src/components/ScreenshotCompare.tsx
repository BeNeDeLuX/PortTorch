import Modal from "./Modal";
import { formatDateTime } from "../lib/formatDate";
import type { DatePrefs } from "../lib/formatDate";

export interface CompareCapture {
  id: string;
  captured_at: string;
  page_title: string | null;
  http_status: number | null;
}

// The before/after view, shared by the Screenshots gallery and the host
// detail page. Extracted rather than duplicated: the two reach it from
// different data shapes but the thing being shown is identical, and a
// second copy would be the one that stops matching.
//
// Wide, because at the default modal width the two figures stack and the
// comparison the dialog exists for is lost. The images are shown whole
// rather than cropped - the difference is often further down the page
// than any thumbnail reaches.
export default function ScreenshotCompare({
  title,
  kind,
  current,
  previous,
  preferences,
  onClose,
  footer,
}: {
  title: string;
  kind: "web" | "rdp";
  current: CompareCapture;
  previous: CompareCapture;
  preferences: DatePrefs;
  onClose: () => void;
  footer?: React.ReactNode;
}) {
  const imageUrl = (id: string) => `/api/${kind === "rdp" ? "rdp-screenshots" : "screenshots"}/${id}/image`;

  return (
    <Modal title={title} wide onClose={onClose}>
      <p className="host-meta">
        What changed between the two captures, side by side. The images are shown in full rather than cropped - the
        difference is often further down the page than a thumbnail can show.
      </p>
      <div className="shot-compare">
        {(
          [
            ["Before", previous],
            ["After", current],
          ] as const
        ).map(([label, capture]) => (
          <figure key={label}>
            <figcaption className="shot-sub">
              {label} · {formatDateTime(capture.captured_at, preferences)}
              {capture.http_status !== null && ` · HTTP ${capture.http_status}`}
              <br />
              {capture.page_title || <em>no title</em>}
            </figcaption>
            <img src={imageUrl(capture.id)} alt={`${label} capture`} />
          </figure>
        ))}
      </div>
      {footer}
    </Modal>
  );
}
