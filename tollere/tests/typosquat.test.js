/**
 * Basic tests for typosquat detection
 * Run with: node --test tests/
 */

import { test } from "node:test";
import assert from "node:assert";
import { detectTyposquat } from "../dist/typosquat.js";

test("detects single-character typo of react", () => {
  const matches = detectTyposquat("raect");
  assert.ok(matches.length > 0);
  assert.strictEqual(matches[0].suspectedTarget, "react");
});

test("detects single-character typo of lodash", () => {
  const matches = detectTyposquat("lodahs");
  assert.ok(matches.length > 0);
  assert.strictEqual(matches[0].suspectedTarget, "lodash");
});

test("detects hyphen/underscore swap", () => {
  const matches = detectTyposquat("react_dom");
  assert.ok(matches.some((m) => m.suspectedTarget.includes("react")));
});

test("does not flag exact match", () => {
  const matches = detectTyposquat("react");
  // Should not flag react as a typosquat of itself
  assert.ok(!matches.some((m) => m.suspectedTarget === "react"));
});

test("does not flag legitimate distinct package", () => {
  const matches = detectTyposquat("kubernetes");
  // Edit distance to all popular packages should be too large
  assert.strictEqual(matches.length, 0);
});

test("detects doubled character", () => {
  const matches = detectTyposquat("axiios");
  assert.ok(matches.some((m) => m.suspectedTarget === "axios"));
});
