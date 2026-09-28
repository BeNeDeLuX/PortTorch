// Turning what someone types into the "Tags" field on Ad-hoc Scans and
// Schedule Scans into the array the API takes - shared so the two forms
// can't drift on what counts as a tag, the same reasoning
// lib/targetList.ts's parser exists for the Target field.
//
// Deliberately light: the server (lib/scanTags.ts) is the actual
// validator - length, count, and what happens on conflict - and returns
// a clear 400 if something's wrong. This only needs to turn a
// comma-separated string into a clean array before that round trip,
// mirroring the comma-joined convention this app already uses for
// port/service/tag filters and multi-recipient email fields.
export function parseTagList(input: string): string[] {
  const seen = new Set<string>();
  const tags: string[] = [];
  for (const raw of input.split(",")) {
    const tag = raw.trim();
    if (!tag || seen.has(tag)) continue;
    seen.add(tag);
    tags.push(tag);
  }
  return tags;
}
