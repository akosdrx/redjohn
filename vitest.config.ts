import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

const uiSrc = fileURLToPath(new URL("./packages/ui/src/index.ts", import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      // Test UI components against source, not dist.
      "@redjohn/ui": uiSrc,
    },
  },
  test: {
    include: [
      "packages/ui/src/**/*.test.{ts,tsx}",
      "app/main/**/*.test.ts",
      "app/renderer/src/**/*.test.{ts,tsx}",
      "tests/**/*.test.ts",
    ],
    environment: "node",
    globals: false,
    setupFiles: ["tests/setup.ts"],
  },
});
