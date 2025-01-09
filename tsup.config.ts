import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/nilql.ts"],
  format: ["esm"],
  clean: true,
  dts: true,
});
