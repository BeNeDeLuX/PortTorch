// The IEEE publishes its MA-L registry as CSV:
//
//   Registry,Assignment,Organization Name,Organization Address
//   MA-L,E80AB9,"Cisco Systems, Inc",80 West Tasman Drive San Jose CA US 94568
//
// Names and addresses are quoted when they contain commas, and an address
// can contain a newline inside its quotes, so this is a real CSV reader
// rather than a split on lines and commas - the live file has more lines
// than records for exactly that reason.

export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          quoted = false;
        }
      } else {
        field += c;
      }
    } else if (c === '"') {
      quoted = true;
    } else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else {
      field += c;
    }
  }
  if (field !== "" || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

// prefix (six upper-case hex digits) -> organisation name. Only MA-L rows:
// the 28- and 36-bit MA-M/MA-S blocks are separate files, and a 24-bit
// lookup would wrongly name the parent block's owner for them.
export function parseOuiCsv(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const [registry, assignment, name] of parseCsv(text)) {
    if (registry?.trim() !== "MA-L") continue;
    const prefix = assignment?.trim().toUpperCase() ?? "";
    const vendor = name?.trim().replace(/\s+/g, " ") ?? "";
    if (/^[0-9A-F]{6}$/.test(prefix) && vendor !== "") out.set(prefix, vendor);
  }
  return out;
}

// nmap's nmap-mac-prefixes: "<hex prefix> <name>" per line, # comments.
// Prefixes are 6, 7 or 9 hex digits (MA-L, MA-M, MA-S). nmap generates it
// from the IEEE registry with shortened names ("Cisco Systems" rather than
// "Cisco Systems, Inc"), and those are the names it writes into
// hosts.mac_vendor - so taking them keeps one manufacturer one name.
export function parseNmapMacPrefixes(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const match = /^([0-9A-Fa-f]{6}(?:[0-9A-Fa-f]|[0-9A-Fa-f]{3})?)\s+(.+)$/.exec(line);
    if (match) out.set(match[1].toUpperCase(), match[2].trim().replace(/\s+/g, " "));
  }
  return out;
}
