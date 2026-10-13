// A host filter carries several values in one comma-joined parameter
// (?macVendor=Ubiquiti,-Espressif). A value containing a comma - a
// manufacturer like "Icann, Iana Department" or "Cisco Systems, Inc" -
// would split into two meaningless values, so a comma inside a value is
// written as "\," and read back. A list without any backslash parses
// exactly as before, so existing URLs and saved searches keep working.
// The server's parseCommaList (search/routes.ts) reads the same grammar.

export function joinFilterList(values: string[]): string {
  return values.map((v) => v.replace(/\\/g, "\\\\").replace(/,/g, "\\,")).join(",");
}

export function parseFilterList(value: string | null | undefined): string[] {
  if (!value) return [];
  const out: string[] = [];
  let current = "";
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === "\\" && i + 1 < value.length && (value[i + 1] === "," || value[i + 1] === "\\")) {
      current += value[++i];
    } else if (c === ",") {
      out.push(current);
      current = "";
    } else {
      current += c;
    }
  }
  out.push(current);
  return out.map((v) => v.trim()).filter(Boolean);
}
