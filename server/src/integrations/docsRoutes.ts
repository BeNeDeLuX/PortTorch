import { Router } from "express";
import helmet from "helmet";
import swaggerUi from "swagger-ui-express";
import { buildOpenApiDocument } from "./openapi";

// Served on its own router, mounted *before* integrationsRouter in app.ts,
// specifically so it sits outside that router's tokenAuth chain: a browser
// loading Swagger UI can't attach a bearer token to its own page load, and
// codegen tooling (openapi-generator, Postman import) expects to fetch a
// spec without credentials. What's exposed is the shape of a handful of endpoints
// and nothing else - no fleet data, no host records, no token material -
// so this is a contract description, not an information leak of scan
// results. The endpoints it documents remain token-authenticated; only
// their description is public.
export const apiDocsRouter = Router();

// The document is rebuilt per request rather than cached at import time -
// it's cheap (a handful of z.toJSONSchema calls), and it means the version
// string in `info` always reflects the running build rather than whatever
// was current when the module first loaded.
apiDocsRouter.get("/openapi.json", (_req, res) => {
  res.json(buildOpenApiDocument());
});

// Swagger UI needs inline <script>/<style> to bootstrap itself, which the
// app-wide helmet() default CSP (script-src 'self') blocks. Rather than
// weakening that policy globally, this re-applies a CSP scoped to this one
// route: same directives, plus 'unsafe-inline' for scripts/styles and
// data: images, and nothing else - notably no external origins, since the
// UI's assets are served locally by swagger-ui-express (important for
// air-gapped/internal deployments, and why a CDN-hosted UI wasn't used).
apiDocsRouter.use(
  "/docs",
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'self'"],
    },
  }),
  swaggerUi.serve,
  swaggerUi.setup(undefined, {
    swaggerOptions: {
      // Points the UI at the generated document rather than embedding a
      // snapshot of it, so the two can never disagree.
      url: "/api/v1/openapi.json",
      persistAuthorization: true,
      // Swagger UI otherwise renders a "valid spec" badge by requesting
      // validator.swagger.io with this deployment's own spec URL as a
      // query parameter - i.e. it tells a third party that a PortTorch
      // instance exists at that address. Unwanted for an internal recon
      // tool, and pointless for an instance that isn't publicly
      // reachable anyway. The scoped CSP above already blocks it; this
      // stops the request being attempted at all rather than leaving a
      // blocked-resource error in the console.
      validatorUrl: null,
    },
    customSiteTitle: "PortTorch External API",
  })
);
