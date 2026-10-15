/** electron-builder beforePack: verify the engine and complete native memory tree. */
import { readFile, lstat, readlink, readdir } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";

async function sha256(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function entries(directory, prefix = "") {
  const names = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (relative === "build-info.json") continue;
    if (entry.isDirectory()) names.push(...await entries(join(directory, entry.name), relative));
    else names.push(relative);
  }
  return names.sort();
}

export default async function checkEngineBundle(context) {
  const directory = join(context.packager.projectDir, "../resources/engine");
  const arch = ["ia32", "x64", "armv7l", "arm64", "universal"][context.arch];
  const metadata = JSON.parse(await readFile(join(directory, "build-info.json"), "utf8"));
  if (metadata.platform !== context.electronPlatformName || metadata.arch !== arch) {
    throw new Error(`Rebuild the engine for ${context.electronPlatformName}/${arch}; found ${metadata.platform}/${metadata.arch}`);
  }
  const name = context.electronPlatformName === "win32" ? "redjohn-engine.exe" : "redjohn-engine";
  const digest = await sha256(join(directory, name));
  if (metadata.sha256 !== digest) throw new Error("Engine changed since its authenticated startup verification; rebuild it");

  const memory = resolve(context.packager.projectDir, "../resources/memory");
  let runtime = null;
  try {
    runtime = JSON.parse(await readFile(join(memory, "build-info.json"), "utf8"));
  } catch {
    runtime = null;
  }

  const hasMatchingMemory =
    runtime &&
    !process.env.SKIP_NATIVE_MEMORY &&
    runtime.platform === context.electronPlatformName &&
    runtime.arch === arch;

  if (!hasMatchingMemory) {
    if (Array.isArray(context.packager.config.extraResources)) {
      context.packager.config.extraResources = context.packager.config.extraResources.filter(
        item => !(item && typeof item === "object" && item.to === "memory")
      );
    }
    if (context.electronPlatformName === "darwin") {
      const minimum = arch === "arm64" ? "14.0" : "15.0";
      context.packager.config.mac = { ...context.packager.config.mac, minimumSystemVersion: minimum };
    }
    return;
  }

  const required = ["openviking-server", "native-memory-services.py", "python/bin/python3"];
  if (runtime.openviking !== "0.5.0" || runtime.openai !== "2.24.0" || runtime.sdk !== "0.1.14" || !runtime.files || required.some(path => !runtime.files[path])) {
    throw new Error("Native memory metadata is incomplete or uses unreviewed service versions");
  }
  const recorded = Object.keys(runtime.files).sort();
  if (JSON.stringify(recorded) !== JSON.stringify(await entries(memory))) {
    throw new Error("Native memory runtime tree changed after verification; rebuild it");
  }
  for (const [relative, item] of Object.entries(runtime.files)) {
    const path = resolve(memory, relative);
    if (!path.startsWith(memory + sep)) throw new Error("Native memory manifest contains an invalid path");
    const stat = await lstat(path);
    if (item.kind === "symlink") {
      if (!stat.isSymbolicLink() || await readlink(path) !== item.target) throw new Error(`Native memory symlink changed: ${relative}`);
    } else if (item.kind === "file") {
      if (!stat.isFile() || await sha256(path) !== item.sha256) {
        throw new Error(`Native memory file changed after verification: ${relative}`);
      }
    } else throw new Error(`Native memory manifest entry is invalid: ${relative}`);
  }
  if (context.electronPlatformName === "darwin") {
    const minimum = arch === "arm64" ? "14.0" : "15.0";
    if (runtime.minimum_macos !== minimum) throw new Error("Native memory minimum macOS version does not match its architecture");
    context.packager.config.mac = { ...context.packager.config.mac, minimumSystemVersion: minimum };
  }
  // Native assessment tools are NOT bundled: the lightweight scanners download
  // on demand into the profile (redjohn_core.tool_provisioner) and heavier tools
  // are optional (resolved from the system PATH), so there is no toolbox to gate.
}
