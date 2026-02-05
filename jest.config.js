const { createDefaultPreset } = require("ts-jest");

const tsJestTransformCfg = createDefaultPreset().transform;

/** @type {import("jest").Config} **/
module.exports = {
  testEnvironment: "node",
  transform: {
    ...tsJestTransformCfg,
  },
  modulePathIgnorePatterns: ["<rootDir>/dist/"],
  testEnvironmentOptions: {
    customExportConditions: ['node', 'node-addons'],
  },
  collectCoverage: true,
  collectCoverageFrom: [
    "src/**/*.ts",
    "!src/server.ts",
    "!src/index.ts",
    "!src/**/__tests__/**"
  ],
  coverageDirectory: "coverage",
  coverageThreshold: {
    global: {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90,
    },
  },
  projects: [
    {
      displayName: "unit",
      testMatch: ["<rootDir>/tests/unit/**/*.test.ts"],
      transform: {
        ...tsJestTransformCfg,
      },
    },
    {
      displayName: "integration",
      testMatch: ["<rootDir>/tests/integration/**/*.test.ts"],
      transform: {
        ...tsJestTransformCfg,
      },
    }
  ]
};