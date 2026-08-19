import { z } from "zod";
import { VERSION } from "../version";
import { adhocScanSchema, cancelScanSchema, lookupSchema, rescanSchema } from "./routes";

// OpenAPI document for the External API (/api/v1) only - deliberately not
// the dashboard's own /api/* routes or the scanner ingest API.
//
// The dashboard API is an internal contract between frontend/src/api.ts
// and these routes; it changes freely alongside the UI, and publishing a
// spec for it would invite external callers to depend on shapes that are
// expected to move. The ingest API is a private scanner<->webserver
// protocol whose only client is the Go scanner in this same repo. /api/v1
// is the one surface with real third-party consumers (SOAR/enrichment
// tooling) who can't read this repo - so it's the one that benefits from
// a machine-readable contract.
//
// Request schemas are generated from the *actual* zod schemas the routes
// validate against (zod 4's native z.toJSONSchema), so a parameter can't
// drift out of the spec without the validation changing too. Responses
// are described by hand and are therefore the part that CAN drift - they
// aren't zod-validated on the way out, so there's nothing to derive them
// from; the integration test asserts the documented paths/operations stay
// in sync with the router, which is the half that can be checked
// mechanically.

// Strips the $schema key zod emits - valid JSON Schema, but noise inside
// an OpenAPI components block.
function jsonSchema(schema: z.ZodType): Record<string, unknown> {
  const { $schema, ...rest } = z.toJSONSchema(schema, { io: "input" }) as Record<string, unknown>;
  void $schema;
  return rest;
}

const errorResponse = {
  description: "Error - the body carries an `error` field with the reason.",
  content: {
    "application/json": {
      schema: {
        type: "object",
        properties: { error: { description: "Human-readable reason, or a zod field-error object for a malformed body." } },
      },
    },
  },
};

const ambiguousResponse = {
  description:
    "Ambiguous host - the same ip/hostname exists under more than one scanner agent. Retry with `scannerAgent` set to one of the returned candidates.",
  content: {
    "application/json": {
      schema: {
        type: "object",
        properties: {
          error: { type: "string" },
          candidates: {
            type: "array",
            items: {
              type: "object",
              properties: {
                id: { type: "string", format: "uuid" },
                ip: { type: "string" },
                hostname: { type: "string", nullable: true },
                scannerAgentName: { type: "string", nullable: true },
              },
            },
          },
        },
      },
    },
  },
};

function jsonBody(schema: z.ZodType) {
  return { required: true, content: { "application/json": { schema: jsonSchema(schema) } } };
}

// Turns a flat zod object schema into OpenAPI query parameters - only
// used for the one GET endpoint, which takes its input from the query
// string rather than a body.
function queryParams(schema: z.ZodType): unknown[] {
  const doc = jsonSchema(schema) as { properties?: Record<string, unknown>; required?: string[] };
  return Object.entries(doc.properties ?? {}).map(([name, prop]) => ({
    name,
    in: "query",
    required: (doc.required ?? []).includes(name),
    schema: prop,
  }));
}

export function buildOpenApiDocument(): Record<string, unknown> {
  return {
    openapi: "3.1.0",
    info: {
      title: "PortTorch External API",
      version: VERSION,
      description:
        "Token-authenticated API for external tooling (SOAR platforms, ticketing, enrichment pipelines): look a host up, " +
        "trigger a rescan of it, stop a running scan, or queue a one-shot ad-hoc scan against a target that isn't a known " +
        "host yet.\n\n" +
        "This covers `/api/v1` only. The dashboard's own `/api/*` routes and the scanner ingest API are internal contracts " +
        "and are deliberately not documented here.\n\n" +
        "Create a token under **Admin → API Tokens**; the plaintext value is shown once.",
    },
    servers: [{ url: "/api/v1" }],
    security: [{ bearerAuth: [] }],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          description:
            "An API token from Admin → API Tokens. Distinct from scanner agent API keys (which authenticate a scanner " +
            "submitting results) and from dashboard session cookies.",
        },
      },
    },
    tags: [
      { name: "Hosts", description: "Look up and act on hosts already known to PortTorch." },
      { name: "Scans", description: "Queue scans against arbitrary targets." },
    ],
    paths: {
      "/hosts/lookup": {
        get: {
          tags: ["Hosts"],
          summary: "Look up a host by IP or hostname",
          description:
            "Returns open ports with service/version fingerprints, correlated CVEs (with EPSS and CISA KEV data), tags, " +
            "and when/by which scanner the host was last seen. Provide `ip` or `hostname`.",
          parameters: queryParams(lookupSchema),
          responses: {
            200: { description: "The host's current enrichment record." },
            400: errorResponse,
            404: { description: "No such host." },
            409: ambiguousResponse,
          },
        },
      },
      "/hosts/rescan": {
        post: {
          tags: ["Hosts"],
          summary: "Rescan a known host's currently-open ports",
          description:
            "Queues a scan request for whichever scanner agent last scanned the host, using its currently known open " +
            "ports as the port spec - the same mechanism as the dashboard's Rescan button.",
          requestBody: jsonBody(rescanSchema),
          responses: {
            201: {
              description: "Scan request queued.",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      scanRequestId: { type: "string", format: "uuid" },
                      status: { type: "string" },
                      createdAt: { type: "string", format: "date-time" },
                      profile: { type: "string", nullable: true, description: "Which NSE profile the request resolved to." },
                    },
                  },
                },
              },
            },
            400: errorResponse,
            404: { description: "No such host." },
            409: ambiguousResponse,
          },
        },
      },
      "/hosts/cancel-scan": {
        post: {
          tags: ["Hosts"],
          summary: "Stop the scan currently running against a host",
          description:
            "Only affects a scan triggered through the rescan/schedule queue. The scanner notices on its next check and " +
            "aborts; this is not an immediate kill.",
          requestBody: jsonBody(cancelScanSchema),
          responses: {
            204: { description: "Cancellation requested." },
            400: errorResponse,
            404: { description: "No such host, or nothing currently running for it." },
            409: ambiguousResponse,
          },
        },
      },
      "/scans/adhoc": {
        post: {
          tags: ["Scans"],
          summary: "Queue a one-shot scan against any target",
          description:
            "The only endpoint here that doesn't require the target to be a known host - for reacting to something " +
            "learned outside PortTorch entirely, e.g. a firewall alert about a newly-seen IP. `targetSpec` accepts an " +
            "IP, CIDR, range, IPv6 list, or a DNS hostname (resolved by the scanner itself, and used as the TLS SNI / " +
            "screenshot hostname for that scan).",
          requestBody: jsonBody(adhocScanSchema),
          responses: {
            201: {
              description: "Scan request queued.",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      scanRequestId: { type: "string", format: "uuid" },
                      status: { type: "string" },
                      createdAt: { type: "string", format: "date-time" },
                      scannerAgentName: { type: "string" },
                      profile: { type: "string", nullable: true },
                      nucleiProfile: { type: "string", nullable: true },
                    },
                  },
                },
              },
            },
            400: errorResponse,
          },
        },
      },
    },
  };
}
