#!/usr/bin/env node

/**
 * Build script — generates CJS + ESM + TypeScript declarations from src/index.js
 * Zero dependencies. Uses Node.js built-ins only.
 */

const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, 'src', 'index.js');
const DIST = path.join(__dirname, 'dist');

// Ensure dist/ exists
if (!fs.existsSync(DIST)) {
  fs.mkdirSync(DIST, { recursive: true });
}

// Read source
const source = fs.readFileSync(SRC, 'utf8');

// ─── CJS Build ───────────────────────────────────────────────────
// Source is already CommonJS, just copy it
fs.writeFileSync(path.join(DIST, 'index.cjs'), source);
console.log('  CJS  → dist/index.cjs');

// ─── ESM Build ───────────────────────────────────────────────────
// Convert module.exports to named exports
const esmSource = source
  .replace("'use strict';\n", '')
  .replace(
    /module\.exports\s*=\s*\{[\s\S]*?\};/,
    `export { Shield, ShieldError, AuthenticationError, RateLimitError, ValidationError, Finding, ScanResult, UsageStats };`
  );

fs.writeFileSync(path.join(DIST, 'index.mjs'), esmSource);
console.log('  ESM  → dist/index.mjs');

// ─── TypeScript Declarations ─────────────────────────────────────
const dts = `/**
 * ClawGuard Shield API Client — TypeScript Declarations
 */

export class ShieldError extends Error {
  statusCode: number;
  errorType: string;
  constructor(message: string, statusCode?: number, errorType?: string);
}

export class AuthenticationError extends ShieldError {
  constructor(message: string, statusCode?: number);
}

export class RateLimitError extends ShieldError {
  limit: number;
  used: number;
  tier: string;
  constructor(message: string, limit?: number, used?: number, tier?: string);
}

export class ValidationError extends ShieldError {
  constructor(message: string);
}

export class Finding {
  patternName: string;
  severity: string;
  category: string;
  matchedText: string;
  lineNumber: number;
  description: string;
  constructor(data: {
    patternName: string;
    severity: string;
    category: string;
    matchedText: string;
    lineNumber?: number;
    description?: string;
  });
  toJSON(): object;
  toString(): string;
}

export class ScanResult {
  clean: boolean;
  riskScore: number;
  severity: string;
  findingsCount: number;
  findings: Finding[];
  scanTimeMs: number;
  readonly isSafe: boolean;
  readonly isCritical: boolean;
  constructor(data: {
    clean: boolean;
    riskScore: number;
    severity: string;
    findingsCount: number;
    findings?: Finding[];
    scanTimeMs?: number;
  });
  toJSON(): object;
  toString(): string;
}

export class UsageStats {
  tier: string;
  tierName: string;
  dailyLimit: number | string;
  todayUsed: number;
  todayRemaining: number | string;
  totalRequests: number;
  totalFindings: number;
  avgResponseTimeMs: number;
  constructor(data: {
    tier: string;
    tierName: string;
    dailyLimit: number | string;
    todayUsed: number;
    todayRemaining: number | string;
    totalRequests?: number;
    totalFindings?: number;
    avgResponseTimeMs?: number;
  });
  toString(): string;
}

export interface ShieldOptions {
  baseUrl?: string;
  timeout?: number;
}

export class Shield {
  static DEFAULT_URL: string;
  apiKey: string;
  baseUrl: string;
  timeout: number;

  constructor(apiKey: string, options?: ShieldOptions);

  scan(text: string, source?: string): Promise<ScanResult>;
  scanBatch(texts: string[], source?: string): Promise<ScanResult[]>;
  health(): Promise<{ status: string; version: string; patterns_count: number }>;
  patterns(): Promise<{ total_patterns: number; categories: object }>;
  usage(): Promise<UsageStats>;
  toString(): string;
}
`;

fs.writeFileSync(path.join(DIST, 'index.d.ts'), dts);
console.log('  DTS  → dist/index.d.ts');

console.log('\\nBuild complete!');
