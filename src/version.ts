/**
 * Single source of truth for the version reported by the CLI (`--version`),
 * the JSON reporter, and the SARIF `tool.driver.version`.
 *
 * Must match package.json — a unit test (tests/unit/version.test.ts) fails
 * the build when the two drift apart, so bump both together on release.
 */
export const VERSION = '0.4.0';
