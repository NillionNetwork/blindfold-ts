import { defineConfig } from "tsup";

export default defineConfig({
  entry: { index: "src/nilql.ts" },
  format: ["esm"],
  clean: true,
  dts: true,
});
