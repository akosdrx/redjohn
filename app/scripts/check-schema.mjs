/** Fail fast if schema.d.ts is missing (run `pnpm schema:generate`). */
import { existsSync } from "node:fs";

if (!existsSync("renderer/src/lib/schema.d.ts")) {
  console.error("renderer/src/lib/schema.d.ts missing — run: pnpm --filter @redjohn/app schema:generate");
  process.exit(1);
}
