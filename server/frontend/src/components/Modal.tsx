import { useEffect } from "react";

// The first generic content modal in this app (Lightbox.tsx is the only
// prior overlay, and it's image-specific) - built for the scan progress
// "Details" popup, but deliberately generic (title + children) so any
// future need for a small popup dialog reuses this instead of hand-rolling
// another one-off overlay. Same escape-to-close / click-backdrop-to-close
// / stopPropagation-on-content conventions as Lightbox.tsx.
// wide widens the panel for content that genuinely needs the room - two
// full-width screenshots side by side, where the default 640px would
// stack them and lose the comparison the dialog exists for.
export default function Modal({
  title,
  onClose,
  wide = false,
  children,
}: {
  title: string;
  onClose: () => void;
  wide?: boolean;
  children: React.ReactNode;
}) {
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className={`modal-panel${wide ? " modal-panel-wide" : ""}`} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>{title}</h3>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            &times;
          </button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}
