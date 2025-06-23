import { defineConfig } from "tsup";

export default defineConfig({
  entry: { index: "src/lib.ts" },
  format: ["esm", "cjs"],
  clean: true,
  dts: true,
});
