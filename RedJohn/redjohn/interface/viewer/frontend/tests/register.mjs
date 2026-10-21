// Tests use Node's runner and the existing pinned TypeScript dependency.
// Production continues to build with Vite; this loader is test-only.
import { register } from "node:module";

register("./typescript-loader.mjs", import.meta.url);
