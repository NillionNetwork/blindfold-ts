import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/nilql.ts"],
  sourcemap: true,
  clean: true,
  dts: true,
});
