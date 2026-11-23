// @ts-check
import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import globals from "globals";
import tseslint from "typescript-eslint";

export default defineConfig(
  {
    ignores: ["**/node_modules/", "**/.wrangler/", "test/fixtures/", "test/e2e/"],
  },
  js.configs.recommended,
  tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: {
          // vitest.config.ts is not part of any tsconfig project.
          allowDefaultProject: ["vitest.config.ts"],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ["eslint.config.js", "vitest.config.ts"],
    languageOptions: { globals: globals.node },
  },
  {
    // This file is plain JavaScript in no tsconfig project, so it gets
    // the syntax rules only.
    files: ["eslint.config.js"],
    extends: [tseslint.configs.disableTypeChecked],
  },
);
