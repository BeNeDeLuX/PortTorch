const CERT_EXPIRY_SOON_DAYS = 30;

export function certExpiryStatus(notAfter: string | null): "expired" | "soon" | "ok" | "unknown" {
  if (!notAfter) return "unknown";
  const daysLeft = (new Date(notAfter).getTime() - Date.now()) / (1000 * 60 * 60 * 24);
  if (daysLeft < 0) return "expired";
  if (daysLeft < CERT_EXPIRY_SOON_DAYS) return "soon";
  return "ok";
}

export function certExpiryLabel(notAfter: string | null): string {
  switch (certExpiryStatus(notAfter)) {
    case "expired":
      return "expired";
    case "soon":
      return "expiring soon";
    case "ok":
      return "valid";
    default:
      return "";
  }
}
