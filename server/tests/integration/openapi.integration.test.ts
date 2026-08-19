import { afterAll, describe, expect, it } from "vitest";
import request from "supertest";
import { closeDb, getApp } from "./helpers";

// The spec's request schemas are generated from the same zod objects the
// routes validate against, so those can't drift. What CAN drift is the
// set of documented paths (hand-written) versus the set the router
// actually exposes - so that's what's asserted mechanically here.
describe("External API OpenAPI document", () => {
  afterAll(async () => {
    await closeDb();
  });

  it("is served without a token, so codegen tooling and the browser UI can fetch it", async () => {
    const res = await request(getApp()).get("/api/v1/openapi.json");
    expect(res.status).toBe(200);
    expect(res.body.openapi).toBe("3.1.0");
  });

  it("documents exactly the four endpoints the router exposes - no more, no fewer", async () => {
    const res = await request(getApp()).get("/api/v1/openapi.json");
    const documented = Object.entries(res.body.paths as Record<string, Record<string, unknown>>)
      .flatMap(([path, ops]) => Object.keys(ops).map((method) => `${method.toUpperCase()} ${path}`))
      .sort();

    expect(documented).toEqual([
      "GET /hosts/lookup",
      "POST /hosts/cancel-scan",
      "POST /hosts/rescan",
      "POST /scans/adhoc",
    ]);
  });

  it("derives request schemas from the real zod schemas, including recently added fields", async () => {
    const res = await request(getApp()).get("/api/v1/openapi.json");
    const adhocProps = res.body.paths["/scans/adhoc"].post.requestBody.content["application/json"].schema.properties;

    // These exist because the route's own zod schema has them - if a field
    // were added to the schema without touching the spec, it would appear
    // here automatically, which is the point of generating rather than
    // hand-writing this half.
    expect(Object.keys(adhocProps).sort()).toEqual(
      ["masscanRate", "nucleiProfile", "portSpec", "profile", "scannerAgent", "targetSpec"].sort()
    );
    // And the constraints come along too, not just the field names.
    expect(adhocProps.masscanRate).toMatchObject({ type: "integer", minimum: 1 });
  });

  it("turns the lookup endpoint's schema into query parameters, not a body", async () => {
    const res = await request(getApp()).get("/api/v1/openapi.json");
    const params = res.body.paths["/hosts/lookup"].get.parameters as Array<{ name: string; in: string }>;
    expect(params.map((p) => p.name).sort()).toEqual(["hostname", "ip", "scannerAgent"]);
    expect(params.every((p) => p.in === "query")).toBe(true);
  });

  it("declares bearer auth as the security scheme for the documented endpoints", async () => {
    const res = await request(getApp()).get("/api/v1/openapi.json");
    expect(res.body.components.securitySchemes.bearerAuth).toMatchObject({ type: "http", scheme: "bearer" });
    expect(res.body.security).toEqual([{ bearerAuth: [] }]);
  });

  it("serves the Swagger UI page itself", async () => {
    const res = await request(getApp()).get("/api/v1/docs/");
    expect(res.status).toBe(200);
    expect(res.text).toContain("swagger-ui");
  });

  it("does not expose the documented endpoints themselves without a token", async () => {
    // The docs router sits in front of tokenAuth, so this guards against
    // accidentally mounting it in a way that bypasses auth for the real
    // endpoints too.
    const res = await request(getApp()).get("/api/v1/hosts/lookup?ip=10.0.0.1");
    expect(res.status).toBe(401);
  });
});
