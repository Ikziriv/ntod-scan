import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Islands build → apps/web/islands/loader.js (gitignored output, served
// statically by the axum ServeDir fallback).
export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: "../web/islands",
    emptyOutDir: true,
    lib: {
      entry: "src/loader.js",
      formats: ["iife"],
      name: "ntodIslands",
    },
    rollupOptions: {
      output: { entryFileNames: "loader.js" },
    },
  },
});
