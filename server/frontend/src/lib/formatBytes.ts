// Binary units (KiB/MiB/GiB) rather than decimal: these are on-disk sizes
// straight from pg_total_relation_size and fs.statSync, which is exactly
// what `du` and every other tool an admin cross-checks against reports.
const UNITS = ["B", "KiB", "MiB", "GiB", "TiB"];

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit++;
  }
  // Whole numbers for bytes, one decimal above that - "1.4 GiB" is the
  // useful precision; "1.4213 GiB" is noise and "1 GiB" hides a lot.
  return `${unit === 0 ? value : value.toFixed(1)} ${UNITS[unit]}`;
}
