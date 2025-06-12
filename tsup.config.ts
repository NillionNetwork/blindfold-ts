import { defineConfig } from "tsup";

export default defineConfig({
  entry: { index: "src/blindfold.ts" },
  format: ["esm", "cjs"],
  clean: true,
  dts: true,
});
