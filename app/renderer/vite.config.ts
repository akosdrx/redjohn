import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  root: __dirname,
  base: "./", // file:// loading in production
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    host: "127.0.0.1",
  },
  build: {
    outDir: "../dist/renderer",
    emptyOutDir: true,
    sourcemap: true,
  },
});
