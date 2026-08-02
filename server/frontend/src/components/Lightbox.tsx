import { useEffect, useState } from "react";

export interface LightboxItem {
  src: string;
  alt: string;
}

export default function Lightbox({
  items,
  initialIndex,
  onClose,
}: {
  items: LightboxItem[];
  initialIndex: number;
  onClose: () => void;
}) {
  const [index, setIndex] = useState(initialIndex);
  const hasMultiple = items.length > 1;

  function showPrev() {
    setIndex((i) => (i - 1 + items.length) % items.length);
  }
  function showNext() {
    setIndex((i) => (i + 1) % items.length);
  }

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
      if (hasMultiple && e.key === "ArrowLeft") showPrev();
      if (hasMultiple && e.key === "ArrowRight") showNext();
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onClose, hasMultiple, items.length]);

  const current = items[index];

  return (
    <div className="lightbox-backdrop" onClick={onClose}>
      <button className="lightbox-close" onClick={onClose} aria-label="Close">
        &times;
      </button>
      {hasMultiple && (
        <button
          className="lightbox-nav lightbox-prev"
          onClick={(e) => {
            e.stopPropagation();
            showPrev();
          }}
          aria-label="Previous"
        >
          &#8249;
        </button>
      )}
      <img className="lightbox-image" src={current.src} alt={current.alt} onClick={(e) => e.stopPropagation()} />
      {hasMultiple && (
        <button
          className="lightbox-nav lightbox-next"
          onClick={(e) => {
            e.stopPropagation();
            showNext();
          }}
          aria-label="Next"
        >
          &#8250;
        </button>
      )}
      {hasMultiple && (
        <div className="lightbox-counter">
          {index + 1} / {items.length}
        </div>
      )}
    </div>
  );
}
