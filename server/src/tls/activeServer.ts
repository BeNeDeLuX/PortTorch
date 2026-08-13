import type { Server } from "https";

// Set once at startup (index.ts, right after the https.Server is
// created) so a route handler elsewhere (settings/routes.ts) can call
// setSecureContext() on the live listener without index.ts needing to
// import a route module directly - that would invert the natural
// dependency direction (routes depend on app wiring, not the other way
// around). null before the server has actually started listening, and
// in any test context that never calls setActiveHttpsServer at all
// (e.g. tests/integration's buildApp()-only setup).
let activeServer: Server | null = null;

export function setActiveHttpsServer(server: Server): void {
  activeServer = server;
}

export function getActiveHttpsServer(): Server | null {
  return activeServer;
}
