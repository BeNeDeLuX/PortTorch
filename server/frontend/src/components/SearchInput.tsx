import { InputHTMLAttributes, useRef } from "react";
import { IconX } from "./icons";

// A search field with a clear button at its right edge, shown once there
// is something to clear. Escape clears too. Used in every page's search
// bar so they all behave alike.
//
// Clearing calls onClear when given - the Dashboard needs it, since its
// search only applies on submit and clearing should also drop the active
// filter - and otherwise reports an empty value through onChange, which
// is all a live-filtering search needs.
export default function SearchInput({
  onClear,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { value: string; onClear?: () => void }) {
  const ref = useRef<HTMLInputElement>(null);

  function clear() {
    if (onClear) onClear();
    else props.onChange?.({ target: { value: "" }, currentTarget: { value: "" } } as React.ChangeEvent<HTMLInputElement>);
    ref.current?.focus();
  }

  return (
    <span className="search-input">
      <input
        {...props}
        ref={ref}
        onKeyDown={(e) => {
          if (e.key === "Escape" && props.value !== "") {
            e.preventDefault();
            clear();
          }
          props.onKeyDown?.(e);
        }}
      />
      {props.value !== "" && (
        <button type="button" className="search-input-clear" onClick={clear} aria-label="Clear search" title="Clear search (Esc)">
          <IconX size={14} />
        </button>
      )}
    </span>
  );
}
