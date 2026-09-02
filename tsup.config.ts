import { defineConfig } from "tsup";

const shared = {
  format: ["cjs", "esm"] as const,
  dts: true,
  splitting: false,
  external: ["gw-auth/core"],
};

export default defineConfig([
  {
    ...shared,
    entry: ["src/core/index.ts"],
    outDir: "dist/core",
    clean: true,
  },
  {
    ...shared,
    entry: ["src/nextjs/index.ts"],
    outDir: "dist/nextjs/server",
    clean: true,
  },
  {
    ...shared,
    entry: ["src/nextjs/client/index.ts"],
    outDir: "dist/nextjs/client",
    clean: true,
  },
  {
    ...shared,
    entry: ["src/testing/index.ts"],
    outDir: "dist/testing",
    clean: true,
  },
]);
