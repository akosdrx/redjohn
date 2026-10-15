/** Build Electron main (ESM) with esbuild. --watch for dev. */
import { build, context } from "esbuild";

const opts = {
  entryPoints: ["main/index.ts"],
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  outfile: "dist/main/index.js",
  // electron + electron-store stay external (provided at runtime)
  external: ["electron", "electron-store"],
  sourcemap: true,
  logLevel: "info",
};

if (process.argv.includes("--watch")) {
  const ctx = await context(opts);
  await ctx.watch();
  console.log("[main] watching…");
} else {
  await build(opts);
}
