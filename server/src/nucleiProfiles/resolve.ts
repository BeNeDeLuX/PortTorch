import { db } from "../db";

// A nuclei-profile pick, as sent by the frontend when triggering a rescan
// or creating/editing a schedule - the independent nuclei counterpart to
// scanProfiles/resolve.ts's NSEProfileSelection. "off" (default) means
// nuclei never runs at all for that scan.
export type NucleiProfileSelection =
  | { kind: "off" }
  | { kind: "safe" }
  | { kind: "custom"; profileId: string };

export class NucleiProfileNotFoundError extends Error {
  constructor() {
    super("nuclei profile not found");
  }
}

// SAFE_EXCLUDE_TAGS is the "safe" tier's definition - unlike NSE's "All
// Safe Modules" (nmap's own "safe" script category, unioned with
// Default), nuclei has no single stable "safe" category to point at: its
// tag taxonomy has thousands of entries and grows with every template
// release (see nucleiProfiles/routes.ts's KNOWN_NUCLEI_SEVERITIES comment
// for the real count). So "safe" here is defined the other way around -
// excluding nuclei's own dos/fuzz/intrusive tag conventions - matching
// scanner/internal/api/server.go's resolveNucleiProfile, which must stay
// in sync with this list since it's the Go side that actually resolves
// "safe" into the same exclude-tags for a queue-triggered scan.
export const SAFE_EXCLUDE_TAGS = ["dos", "fuzz", "intrusive"];

// Turns a selection into the three snapshot columns scan_requests/
// scan_schedules actually store - see resolveNSEProfile's doc comment for
// why this is a snapshot, never a live join: an "off"/"safe" selection
// never touches nuclei_profiles at all (there's nothing to look up), and
// "custom" resolves the named profile's current tags into a snapshot
// copied once at call time - a later edit/delete of that nuclei_profiles
// row can never retroactively change what's already been captured here.
export async function resolveNucleiProfile(
  selection: NucleiProfileSelection
): Promise<{ nucleiProfile: "off" | "safe" | "custom"; nucleiTags: string[] | null; nucleiProfileLabel: string }> {
  if (selection.kind === "off") {
    return { nucleiProfile: "off", nucleiTags: null, nucleiProfileLabel: "Off" };
  }
  if (selection.kind === "safe") {
    return { nucleiProfile: "safe", nucleiTags: null, nucleiProfileLabel: "Safe" };
  }
  const profile = await db
    .selectFrom("nuclei_profiles")
    .select(["name", "tags"])
    .where("id", "=", selection.profileId)
    .executeTakeFirst();
  if (!profile) throw new NucleiProfileNotFoundError();
  return { nucleiProfile: "custom", nucleiTags: profile.tags, nucleiProfileLabel: profile.name };
}
