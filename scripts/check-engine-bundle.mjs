#!/usr/bin/env node
import checkEngineBundle from "../app/scripts/check-engine-bundle.mjs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = resolve(__dirname, "..");
const projectDir = resolve(rootDir, "app");
const arch = process.arch === "arm64" ? 3 : 1;
const electronPlatformName = process.platform;

try {
  await checkEngineBundle({
    packager: { projectDir, config: { mac: {} } },
    arch,
    electronPlatformName
  });
  console.log("checkEngineBundle PASSED!");
  process.exit(0);
} catch (err) {
  console.error("checkEngineBundle FAILED:", err);
  process.exit(1);
}
