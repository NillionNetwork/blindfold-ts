import { defineConfig } from "vite";
import tsconfigPaths from "vite-tsconfig-paths";

export default defineConfig((_config) => ({
  plugins: [tsconfigPaths()],
  test: {
    testTimeout: 80000,
    coverage: {
      enabled: true,
      reporter: ["text", "json-summary", "json", "lcov"],
      reportOnFailure: true,
      exclude: ["./*.config.ts", "./bin/check-version.ts"],
    },
  },
}));
