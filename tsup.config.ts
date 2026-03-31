import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/**/*.ts", "src/**/*.tsx"], // Your entry file(s)
  format: ["cjs", "esm"], // Output both CommonJS (.cjs) and ESM (.js/.mjs)
  dts: true, // Generate .d.ts files for both formats
  splitting: false,
  clean: true, // Clean dist folder before build
});
