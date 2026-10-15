/**
 * Build the preload as CJS (.cjs). Sandboxed preload scripts cannot use
 * ESM, so this is deliberately separate from the ESM main build.
 */
import { build, context } from "esbuild";

const opts = {
  entryPoints: ["preload/index.ts"],
  bundle: true,
  platform: "node",
  target: "node20",
  format: "cjs",
  outfile: "dist/preload/index.cjs",
  external: ["electron"],
  sourcemap: true,
  logLevel: "info",
};

if (process.argv.includes("--watch")) {
  const ctx = await context(opts);
  await ctx.watch();
  console.log("[preload] watching…");
} else {
  await build(opts);
}
