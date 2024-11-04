// @ts-check

import js from "@eslint/js";
import json from "@eslint/json";
import markdown from "@eslint/markdown";
import jest from "eslint-plugin-jest";
import simpleImportSort from "eslint-plugin-simple-import-sort";
import tsDoc from "eslint-plugin-tsdoc";
import globals from "globals";
import ts from "typescript-eslint";

export default ts.config(
  {
    ignores: [
      "**/dist",
      "**/coverage"
    ],
  },
  ...ts.configs.strictTypeChecked,
  ...ts.configs.stylisticTypeChecked,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      globals: globals.browser,
      parserOptions: {
        project: true,
        tsconfigDirName: import.meta.dirname,
      },
    },
    plugins: {
      "@typescript-eslint": ts.plugin,
    },
    rules: {
      "@typescript-eslint/no-non-null-assertion": "off",
      "@typescript-eslint/prefer-nullish-coalescing": "off",
      "@typescript-eslint/no-unnecessary-condition": "off",
      "@typescript-eslint/no-extraneous-class": "off",
      "@typescript-eslint/no-unused-vars": [
        "off",
        {
          args: "all",
          argsIgnorePattern: "^_",
          caughtErrors: "all",
          destructuredArrayIgnorePattern: "^_",
          ignoreRestSiblings: true,
          varsIgnorePattern: "^_",
        },
      ],
      "@typescript-eslint/restrict-template-expressions": [
        "off",
        {
          allowAny: true,
          allowBoolean: true,
          allowNullish: true,
          allowNumber: true,
        },
      ],
    },
  },
  {
    files: ["**/*.{js,mjs}"],
    languageOptions: {
      globals: {
        ...globals.node,
        process: "readonly",
      },
    },
    ...js.configs.recommended,
    // Workaround to disable rules applied earlier which aren't correctly scoped to `{ts,tsx}`.
    ...ts.configs.disableTypeChecked,
  },
  {
    files: ["**/*.{js,jsx,ts,tsx,mjs}"],
    plugins: {
      "simple-import-sort": simpleImportSort,
      tsdoc: tsDoc,
    },
    rules: {
      "simple-import-sort/exports": "error",
      "simple-import-sort/imports": [
        "error",
        {
          groups: [
            // Side effect imports.
            ["^\\u0000"],
            // `react` related packages come first.
            ["^react", "^@?\\w"],
            // Node.js builtins prefixed with `node:`.
            ["^node:"],
            // Packages.
            // Things that start with a letter (or digit or underscore), or `@` followed by a letter.
            ["^@?\\w"],
            // @nillion packages (your monorepo packages)
            ["^@nillion/"],
            // Absolute imports and other imports such as Vue-style `@/foo`.
            // Anything not matched in another group.
            ["^"],
            // Relative imports.
            // Anything that starts with a dot.
            ["^\\."],
          ],
        },
      ],
      "tsdoc/syntax": "warn",
    },
  },
  {
    files: ["**/*.test.ts"],
    languageOptions: {
      globals: {
        ...jest.environments.globals.globals,
      },
    },
    plugins: {
      jest,
    },
    rules: {
      ...jest.configs.style.rules,
      "@typescript-eslint/no-non-null-assertion": "off",
      "jest/no-conditional-expect": "off",
    },
  },
  {
    plugins: {
      json,
    },
    files: ["**/*.json"],
    language: "json/json",
    rules: {
      "json/no-duplicate-keys": "warn",
      // Workaround to disable rules applied earlier which aren't correctly scoped to `{ts,tsx}`.
      ...ts.configs.disableTypeChecked.rules,
    },
  },
  {
    files: ["**/*.md"],
    plugins: {
      markdown,
    },
    language: "markdown/commonmark",
    rules: {
      "markdown/no-html": "error",
      // Workaround to disable rules applied earlier which aren't correctly scoped to `{ts,tsx}`.
      ...ts.configs.disableTypeChecked.rules,
    },
  },
);
