import { TRIAGE_FILTER_OPTIONS, TriageFilter } from "../lib/triageFilter";

// A labelled <select> rather than another row of chips: the seven options
// are mutually exclusive and several are only occasionally wanted, which
// is exactly what a dropdown expresses and a chip row does not - the
// severity/KEV chips above it stay chips because those are the everyday
// ones. It also drops into the same .list-controls row the checkbox it
// replaced already occupied, so neither page grew a new row of controls.
export default function TriageFilterSelect({
  value,
  onChange,
}: {
  value: TriageFilter;
  onChange: (next: TriageFilter) => void;
}) {
  return (
    <label className="triage-filter">
      Triage:{" "}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as TriageFilter)}
        title="Which triage state to show. 'Needs a decision' is untriaged findings plus ones whose decision has expired."
      >
        {TRIAGE_FILTER_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}
