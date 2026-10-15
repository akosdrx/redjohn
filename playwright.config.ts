/**
 * Playwright E2E config — TEMPLATE.
 *
 * Electron e2e uses Playwright's `_electron` launcher (no webServer).
 * Required setup before running:
 *   pnpm add -D -w @playwright/test
 *   pnpm exec playwright install   # not needed for _electron, but harmless
 *   pnpm build                      # dist/ must exist
 *   pnpm exec playwright test --config playwright.config.ts
 *
 * A REDJOHN_ENGINE_CMD pointing at a runnable engine (or a demo stub) is
 * required for real end-to-end flows.
 */
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  retries: 0,
  use: {
    trace: "retain-on-failure",
  },
  // Example test (tests/e2e/app.spec.ts):
  //
  //   import { _electron as electron, test, expect } from "@playwright/test";
  //   test("launches and shows the sidebar", async () => {
  //     const app = await electron.launch({
  //       args: ["app/dist/main/index.js"],
  //       env: { ...process.env, REDJOHN_ENGINE_CMD: "python -m redjohn_core.serve" },
  //     });
  //     const page = await app.firstWindow();
  //     await expect(page.getByText("RedJohn")).toBeVisible();
  //     await app.close();
  //   });
});
