import fs from "fs";
import path from "path";

// Walk upward from this file looking for package.json rather than a fixed
// "../../package.json" - that relative depth only holds when running the
// compiled dist/src/version.ts (two levels under server/). Running the
// source directly instead (src/version.ts - one level under server/, as
// `npm run dev`'s tsx and these integration tests both do) would resolve
// "../../package.json" to the repo root, which has no package.json at all
// and throws at import time. A static `import "../package.json"` has the
// same problem in reverse (right for src/, wrong for dist/src/), and
// lives outside tsconfig's rootDir besides. Walking up avoids hardcoding
// either depth.
function findPackageJson(startDir: string): string {
  let dir = startDir;
  for (let i = 0; i < 5; i++) {
    const candidate = path.join(dir, "package.json");
    if (fs.existsSync(candidate)) return candidate;
    dir = path.join(dir, "..");
  }
  throw new Error(`could not locate package.json above ${startDir}`);
}

const pkg = JSON.parse(fs.readFileSync(findPackageJson(__dirname), "utf8")) as { version: string };

export const VERSION: string = pkg.version;
