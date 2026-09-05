// Shown when a fleet-wide finding page hit its server-side ceiling. The
// page is then showing part of the picture, and saying so is the whole
// point - a list that silently omits findings is one that gets trusted
// for something it can no longer do.
export default function TruncationNotice({
  total,
  limit,
  noun,
}: {
  total: number;
  limit: number;
  noun: string;
}) {
  return (
    <p className="callout-warning">
      Showing the first {limit.toLocaleString()} of {total.toLocaleString()} {noun}. Narrow the search or the filters
      to see the rest - the export below covers only what is shown here, for the same reason.
    </p>
  );
}
