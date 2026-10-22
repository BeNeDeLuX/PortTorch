// A certificate fingerprint as people paste it - "BB:A4:D2:B3:...", with
// spaces, or as plain hex - reduced to the stored form: lower-case hex,
// no separators. Returns null when the text is not plausibly (part of) a
// fingerprint, so a short query like a port number "443" does not start
// matching fingerprints that happen to contain those digits.
export const MIN_FINGERPRINT_QUERY = 8;

export function fingerprintQuery(text: string): string | null {
  const hex = text.trim().toLowerCase().replace(/[\s:-]/g, "");
  return hex.length >= MIN_FINGERPRINT_QUERY && /^[0-9a-f]+$/.test(hex) ? hex : null;
}
