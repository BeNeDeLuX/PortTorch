import { z } from "zod";

// How long a scan target may be, and why there is a limit at all.
//
// pipeline.RunMasscan passes the whole target spec to masscan as a
// *single* argv entry, and Linux caps one argument at MAX_ARG_STRLEN -
// 32 pages, 131072 bytes. Measured against real masscan 1.3.2 rather
// than assumed: 8200 comma-separated addresses (92 KB) ran fine, 20000
// (229 KB) failed before masscan even started, with nothing but the
// kernel's own "Argument list too long".
//
// Until this existed nothing validated the length anywhere, so an
// over-long spec was accepted, queued, claimed by a scanner and only
// then failed - with an error that says nothing about the target list
// and an hour of queue time already spent. Half the ceiling leaves room
// for the rest of the command line and still allows roughly four
// thousand worst-case addresses; anything larger is better expressed as
// CIDRs, or split across scans.
export const MAX_TARGET_SPEC_LENGTH = 65536;

// The shared schema every *caller-supplied* target goes through - the
// dashboard's ad-hoc form, the External API's own ad-hoc endpoint,
// schedule create/update, and the estimate endpoint. Deliberately not
// applied to ingest's own scan-job report: that one comes back *from* a
// scanner describing a scan it already ran, where rejecting it would
// lose the record of real work.
export const targetSpecSchema = z
  .string()
  .trim()
  .min(1)
  .max(MAX_TARGET_SPEC_LENGTH, `target is longer than ${MAX_TARGET_SPEC_LENGTH} characters - masscan takes the whole list as one argument and the operating system refuses one this long. Split the scan, or use CIDRs where the list covers whole subnets.`);
