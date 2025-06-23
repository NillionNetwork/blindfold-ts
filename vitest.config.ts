import { defineConfig } from "vite";
import tsconfigPaths from "vite-tsconfig-paths";

export default defineConfig((_config) => ({
  plugins: [tsconfigPaths()],
  test: {
    coverage: {
      reporter: ["text", "json-summary", "json", "lcov"],
      reportOnFailure: true,
    },
  },
}));
