import { LIFECYCLE_CAVEAT, lifecycleOf } from "../lib/softwareLifecycle";

// "End of life" or "ends soon" beside a product version, nothing at all
// otherwise. The one place this is rendered, so the caveat about
// distribution backports always travels with the claim.
export default function LifecycleBadge({ product, version }: { product: string | null; version: string | null }) {
  if (!product) return null;
  const life = lifecycleOf(product, version);
  if (!life) return null;
  return (
    <span className={`lifecycle-badge lifecycle-${life.status}`} title={`${life.label}. ${LIFECYCLE_CAVEAT}`}>
      {life.status === "ended" ? "end of life" : `EOL ${life.date}`}
    </span>
  );
}
