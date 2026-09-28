import { z } from "zod";

// The tags an ad-hoc scan or a schedule can optionally carry, and the one
// place every write path (the dashboard's own ad-hoc/schedule routes, the
// External API's ad-hoc endpoint) validates and normalizes them - so they
// can't drift on the cap, the per-tag shape, or what an empty submission
// means, the same "one shared module" reasoning targetSpecSchema and
// resolveNSEProfile already follow for their own fields.
//
// Same per-tag shape as the existing single-tag-add endpoint
// (search/routes.ts's tagSchema: trimmed, 1-64 chars, no charset
// restriction) - a scan tag is stored in the exact same host_tags table,
// so inventing a stricter rule here would just mean two different
// answers to "what is a valid tag" in one app.
export const MAX_SCAN_TAGS = 20;

export const scanTagsSchema = z.array(z.string().trim().min(1).max(64)).max(MAX_SCAN_TAGS).optional();

// Dedupes (case-sensitive, matching host_tags' own exact-string identity)
// and collapses an empty result to null rather than storing `{}` - NULL
// is what "no tags requested" has always meant on these columns, and a
// caller sending `tags: []` explicitly (rather than omitting the field)
// should mean the same thing, not a third empty-but-present state nothing
// downstream distinguishes anyway. Also accepts null directly, which
// PATCH /api/schedules/:id uses to explicitly clear a schedule's tags
// back to none - see scanTagsSchema.nullable() there.
export function normalizeScanTags(tags: string[] | null | undefined): string[] | null {
  if (!tags || tags.length === 0) return null;
  const deduped = [...new Set(tags)];
  return deduped.length > 0 ? deduped : null;
}
