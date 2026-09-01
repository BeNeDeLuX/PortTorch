import { URL } from "url";
import type { HecSettings } from "../settings/appSettings";
import { outboundPost } from "../lib/outboundPost";
import { serializeBatch, type HecEvent } from "./format";

// Splunk's own path, and the one every HEC-compatible collector accepts.
// The admin enters a base URL, so this is appended rather than being part
// of what they type - but a URL that already ends in /services/collector
// is left alone, since that is the form most vendor documentation shows.
export function collectorUrl(baseUrl: string): string {
  const trimmed = baseUrl.trim().replace(/\/+$/, "");
  if (/\/services\/collector(\/event)?$/.test(trimmed)) return trimmed;
  return `${trimmed}/services/collector/event`;
}

export interface HecPostResult {
  ok: boolean;
  status?: number;
  error?: string;
}

// The transport is lib/outboundPost - shared with webhook delivery, which
// needs the same two things fetch cannot give: a CA bundle and
// rejectUnauthorized.
// ca: admin-uploaded trust anchors plus Node's public roots, so an
// internally hosted collector with a private CA verifies properly rather
// than needing verification switched off (see settings/caCertificates.ts).
export async function postToHec(settings: HecSettings, events: HecEvent[], ca?: string[]): Promise<HecPostResult> {
  if (!settings.url || !settings.token) {
    return { ok: false, error: "no collector URL or token configured" };
  }
  if (events.length === 0) return { ok: true };

  const result = await outboundPost(collectorUrl(settings.url), serializeBatch(events), {
    // "Splunk <token>" is the scheme every HEC implementation expects.
    headers: { Authorization: `Splunk ${settings.token}` },
    verifyTls: settings.verifyTls,
    ca,
  });
  // The collector's own wording, so an admin sees what it actually said.
  return result.ok ? result : { ...result, error: result.error?.replace("target responded", "collector returned") };
}
