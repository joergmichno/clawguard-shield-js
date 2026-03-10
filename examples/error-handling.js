/**
 * Error handling example — handle all SDK error types gracefully.
 *
 * Usage:
 *   CLAWGUARD_API_KEY=cgs_your_key node examples/error-handling.js
 */

const {
  Shield,
  ShieldError,
  AuthenticationError,
  RateLimitError,
  ValidationError,
} = require('clawguard-shield');

async function safeScan(shield, text) {
  try {
    return await shield.scan(text);
  } catch (err) {
    if (err instanceof AuthenticationError) {
      // Invalid or expired API key
      console.error('Auth failed — check your CLAWGUARD_API_KEY');
      console.error(`  Status: ${err.statusCode}, Type: ${err.errorType}`);
      return null;
    }

    if (err instanceof RateLimitError) {
      // Daily scan limit exceeded
      console.warn(`Rate limited — ${err.used}/${err.limit} scans used (${err.tier} tier)`);
      console.warn('Upgrade at https://prompttools.co/pricing');
      return null;
    }

    if (err instanceof ValidationError) {
      // Invalid input (empty text, text too long, etc.)
      console.error('Validation error:', err.message);
      return null;
    }

    if (err instanceof ShieldError) {
      // Other API error (500, network issue, etc.)
      console.error(`Shield API error: ${err.message} (${err.statusCode})`);
      return null;
    }

    // Unexpected error
    throw err;
  }
}

async function main() {
  // 1. Constructor validates API key format
  try {
    new Shield('invalid_key');
  } catch (err) {
    console.log('Constructor validation:', err.message);
  }

  // 2. Normal usage with error handling
  const apiKey = process.env.CLAWGUARD_API_KEY;
  if (!apiKey) {
    console.error('Set CLAWGUARD_API_KEY environment variable');
    process.exit(1);
  }

  const shield = new Shield(apiKey);

  // Health check (no auth required) — good for connection testing
  try {
    const health = await shield.health();
    console.log(`\nAPI healthy: ${health.status}, ${health.patterns_count} patterns`);
  } catch (err) {
    console.error('Cannot reach Shield API:', err.message);
    process.exit(1);
  }

  // Scan with full error handling
  const result = await safeScan(shield, 'Hello, how are you?');
  if (result) {
    console.log(`\nScan result: clean=${result.clean}, severity=${result.severity}`);
  }

  // Check usage to avoid rate limits proactively
  try {
    const usage = await shield.usage();
    console.log(`\nUsage: ${usage.todayUsed}/${usage.dailyLimit} scans (${usage.tierName})`);
    if (usage.todayRemaining < 10) {
      console.warn('Warning: Running low on daily scans!');
    }
  } catch (err) {
    console.error('Could not fetch usage:', err.message);
  }
}

main().catch(console.error);
