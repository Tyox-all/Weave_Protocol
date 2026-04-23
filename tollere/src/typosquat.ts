/**
 * Typosquat detection
 * Checks if a package name is suspiciously similar to a popular package
 */

import type { TyposquatMatch } from "./types.js";

// Top popular npm packages - common typosquat targets
// In production, this would be loaded from a regularly-updated source
const POPULAR_PACKAGES = [
  "react", "lodash", "axios", "express", "vue", "angular", "next",
  "typescript", "webpack", "babel", "eslint", "prettier", "jest",
  "mocha", "chai", "moment", "uuid", "dotenv", "chalk", "commander",
  "yargs", "inquirer", "request", "fs-extra", "glob", "rimraf",
  "cross-env", "concurrently", "nodemon", "ts-node", "tsx",
  "openai", "anthropic", "@anthropic-ai/sdk", "langchain",
  "@langchain/core", "@modelcontextprotocol/sdk", "llamaindex",
  "@google/generative-ai", "cohere-ai", "@huggingface/inference",
  "tensorflow", "@tensorflow/tfjs", "onnxruntime-node",
  "puppeteer", "playwright", "cheerio", "jsdom",
  "stripe", "twilio", "sendgrid", "@sendgrid/mail",
  "mongoose", "pg", "mysql2", "sqlite3", "redis", "ioredis",
  "passport", "jsonwebtoken", "bcrypt", "bcryptjs", "argon2",
  "helmet", "cors", "compression", "morgan", "winston", "pino",
  "socket.io", "ws", "graphql", "apollo-server", "@apollo/client",
  "vite", "rollup", "esbuild", "swc", "parcel",
  "tailwindcss", "@emotion/react", "styled-components",
  "redux", "@reduxjs/toolkit", "zustand", "jotai", "recoil",
];

/**
 * Compute Levenshtein edit distance between two strings
 */
function editDistance(a: string, b: string): number {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix: number[][] = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1,
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Compute similarity (0-1) between two strings
 */
function similarity(a: string, b: string): number {
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 1;
  return 1 - editDistance(a, b) / maxLen;
}

/**
 * Common typosquat patterns
 */
function detectPatterns(packageName: string, target: string): boolean {
  const lower = packageName.toLowerCase();
  const targetLower = target.toLowerCase();

  // Same package, no typosquat
  if (lower === targetLower) return false;

  // Hyphen/underscore swap: react-dom -> react_dom
  if (lower.replace(/-/g, "_") === targetLower.replace(/-/g, "_")) return true;
  if (lower.replace(/_/g, "-") === targetLower.replace(/_/g, "-")) return true;

  // Number substitution: l33t -> leet, w3 -> we
  const deNumbered = lower
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t");
  if (deNumbered === targetLower) return true;

  // Doubled chars: reactt, lodashh
  if (lower.replace(/(.)\1+/g, "$1") === targetLower) return true;

  // Missing/extra dash: reactnative vs react-native
  if (lower.replace(/-/g, "") === targetLower.replace(/-/g, "")) return true;

  // Scope confusion: types-x vs @types/x, react-dom vs @react/dom
  if (lower.startsWith("types-") && targetLower === `@types/${lower.slice(6)}`) return true;

  return false;
}

/**
 * Check if a package name is a likely typosquat
 */
export function detectTyposquat(packageName: string): TyposquatMatch[] {
  const matches: TyposquatMatch[] = [];
  const cleanName = packageName.toLowerCase().trim();

  for (const target of POPULAR_PACKAGES) {
    const targetClean = target.toLowerCase();

    // Skip exact matches
    if (cleanName === targetClean) continue;

    const dist = editDistance(cleanName, targetClean);
    const sim = similarity(cleanName, targetClean);
    const patternMatch = detectPatterns(cleanName, targetClean);

    // Suspicious if:
    // - Edit distance 1 (single char typo) on any name >= 3 chars
    // - Edit distance 2 with similarity >= 0.6 (catches char swaps like raect/react)
    // - Pattern match detected (hyphen swaps, doubled chars, etc.)
    const isShortNameSingleTypo = dist === 1 && targetClean.length >= 3;
    const isReasonableTypo = dist === 2 && sim >= 0.6;
    if (isShortNameSingleTypo || isReasonableTypo || patternMatch) {
      matches.push({
        suspectedTarget: target,
        similarity: sim,
        editDistance: dist,
      });
    }
  }

  // Sort by similarity, highest first
  matches.sort((a, b) => b.similarity - a.similarity);

  // Return top 3 matches
  return matches.slice(0, 3);
}

/**
 * Get list of popular packages (useful for testing)
 */
export function getPopularPackages(): string[] {
  return [...POPULAR_PACKAGES];
}
