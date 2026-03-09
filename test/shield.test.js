/**
 * ClawGuard Shield JS SDK — Tests
 *
 * Uses Node.js built-in test runner (node --test).
 * Requires Node.js >= 18.
 */

const { describe, it, mock, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const {
  Shield,
  ShieldError,
  AuthenticationError,
  RateLimitError,
  ValidationError,
  Finding,
  ScanResult,
  UsageStats,
} = require('../src/index.js');

// ─── Constructor Tests ───────────────────────────────────────────

describe('Shield constructor', () => {
  it('should create instance with valid API key', () => {
    const shield = new Shield('cgs_test_key_123');
    assert.equal(shield.apiKey, 'cgs_test_key_123');
    assert.equal(shield.baseUrl, 'https://prompttools.co/api/v1');
    assert.equal(shield.timeout, 10000);
  });

  it('should accept custom options', () => {
    const shield = new Shield('cgs_test', {
      baseUrl: 'https://custom.api.com/v1/',
      timeout: 5000,
    });
    assert.equal(shield.baseUrl, 'https://custom.api.com/v1');
    assert.equal(shield.timeout, 5000);
  });

  it('should strip trailing slashes from baseUrl', () => {
    const shield = new Shield('cgs_test', { baseUrl: 'https://api.com/v1///' });
    assert.equal(shield.baseUrl, 'https://api.com/v1');
  });

  it('should throw AuthenticationError for empty key', () => {
    assert.throws(
      () => new Shield(''),
      (err) => {
        assert(err instanceof AuthenticationError);
        assert.equal(err.message, 'API key is required.');
        return true;
      }
    );
  });

  it('should throw AuthenticationError for invalid key format', () => {
    assert.throws(
      () => new Shield('sk_invalid_key'),
      (err) => {
        assert(err instanceof AuthenticationError);
        assert(err.message.includes('cgs_'));
        return true;
      }
    );
  });

  it('should throw AuthenticationError for undefined key', () => {
    assert.throws(() => new Shield(undefined), AuthenticationError);
    assert.throws(() => new Shield(null), AuthenticationError);
  });

  it('should have correct toString()', () => {
    const shield = new Shield('cgs_test_key_12345');
    assert.equal(shield.toString(), 'Shield(key=cgs_test_key..., url=https://prompttools.co/api/v1)');
  });
});

// ─── Finding Tests ───────────────────────────────────────────────

describe('Finding', () => {
  it('should create with all fields', () => {
    const finding = new Finding({
      patternName: 'Instruction Override',
      severity: 'HIGH',
      category: 'prompt_injection',
      matchedText: 'ignore previous instructions',
      lineNumber: 1,
      description: 'Attempts to override system prompt',
    });
    assert.equal(finding.patternName, 'Instruction Override');
    assert.equal(finding.severity, 'HIGH');
    assert.equal(finding.lineNumber, 1);
  });

  it('should have default values for optional fields', () => {
    const finding = new Finding({
      patternName: 'Test',
      severity: 'LOW',
      category: 'test',
      matchedText: 'test',
    });
    assert.equal(finding.lineNumber, 0);
    assert.equal(finding.description, '');
  });

  it('should serialize to JSON', () => {
    const finding = new Finding({
      patternName: 'Test',
      severity: 'HIGH',
      category: 'pi',
      matchedText: 'test',
    });
    const json = finding.toJSON();
    assert.equal(json.patternName, 'Test');
    assert.equal(json.severity, 'HIGH');
  });

  it('should have descriptive toString()', () => {
    const finding = new Finding({
      patternName: 'Override',
      severity: 'HIGH',
      category: 'pi',
      matchedText: 'x',
    });
    assert.equal(finding.toString(), 'Finding(HIGH: Override)');
  });
});

// ─── ScanResult Tests ────────────────────────────────────────────

describe('ScanResult', () => {
  it('should create clean result', () => {
    const result = new ScanResult({
      clean: true,
      riskScore: 0,
      severity: 'CLEAN',
      findingsCount: 0,
    });
    assert.equal(result.clean, true);
    assert.equal(result.isSafe, true);
    assert.equal(result.isCritical, false);
    assert.equal(result.riskScore, 0);
  });

  it('should create result with findings', () => {
    const finding = new Finding({
      patternName: 'Test',
      severity: 'HIGH',
      category: 'pi',
      matchedText: 'test',
    });
    const result = new ScanResult({
      clean: false,
      riskScore: 8,
      severity: 'HIGH',
      findingsCount: 1,
      findings: [finding],
      scanTimeMs: 5,
    });
    assert.equal(result.clean, false);
    assert.equal(result.isSafe, false);
    assert.equal(result.findings.length, 1);
    assert.equal(result.scanTimeMs, 5);
  });

  it('should detect CRITICAL severity', () => {
    const result = new ScanResult({
      clean: false,
      riskScore: 10,
      severity: 'CRITICAL',
      findingsCount: 3,
    });
    assert.equal(result.isCritical, true);
  });

  it('should have default values', () => {
    const result = new ScanResult({
      clean: true,
      riskScore: 0,
      severity: 'CLEAN',
      findingsCount: 0,
    });
    assert.deepEqual(result.findings, []);
    assert.equal(result.scanTimeMs, 0);
  });

  it('should have descriptive toString()', () => {
    const clean = new ScanResult({
      clean: true,
      riskScore: 0,
      severity: 'CLEAN',
      findingsCount: 0,
      scanTimeMs: 3,
    });
    assert.equal(clean.toString(), 'ScanResult(CLEAN, risk=0/10, 3ms)');

    const dirty = new ScanResult({
      clean: false,
      riskScore: 8,
      severity: 'HIGH',
      findingsCount: 2,
      scanTimeMs: 5,
    });
    assert.equal(dirty.toString(), 'ScanResult(HIGH (2 findings), risk=8/10, 5ms)');
  });

  it('should serialize to JSON', () => {
    const result = new ScanResult({
      clean: false,
      riskScore: 5,
      severity: 'MEDIUM',
      findingsCount: 1,
      findings: [
        new Finding({
          patternName: 'Test',
          severity: 'MEDIUM',
          category: 'pi',
          matchedText: 'x',
        }),
      ],
    });
    const json = result.toJSON();
    assert.equal(json.clean, false);
    assert.equal(json.findings.length, 1);
    assert.equal(json.findings[0].patternName, 'Test');
  });
});

// ─── UsageStats Tests ────────────────────────────────────────────

describe('UsageStats', () => {
  it('should create with all fields', () => {
    const stats = new UsageStats({
      tier: 'free',
      tierName: 'Free',
      dailyLimit: 100,
      todayUsed: 42,
      todayRemaining: 58,
      totalRequests: 1000,
      totalFindings: 250,
      avgResponseTimeMs: 6.5,
    });
    assert.equal(stats.tier, 'free');
    assert.equal(stats.todayUsed, 42);
    assert.equal(stats.totalRequests, 1000);
    assert.equal(stats.avgResponseTimeMs, 6.5);
  });

  it('should have default values', () => {
    const stats = new UsageStats({
      tier: 'pro',
      tierName: 'Pro',
      dailyLimit: 'unlimited',
      todayUsed: 500,
      todayRemaining: 'unlimited',
    });
    assert.equal(stats.totalRequests, 0);
    assert.equal(stats.totalFindings, 0);
    assert.equal(stats.avgResponseTimeMs, 0);
  });

  it('should have descriptive toString()', () => {
    const stats = new UsageStats({
      tier: 'free',
      tierName: 'Free',
      dailyLimit: 100,
      todayUsed: 42,
      todayRemaining: 58,
    });
    assert.equal(stats.toString(), 'UsageStats(Free: 42/100 today)');
  });
});

// ─── Error Classes Tests ─────────────────────────────────────────

describe('Error classes', () => {
  it('ShieldError should extend Error', () => {
    const err = new ShieldError('test', 500, 'server_error');
    assert(err instanceof Error);
    assert(err instanceof ShieldError);
    assert.equal(err.message, 'test');
    assert.equal(err.statusCode, 500);
    assert.equal(err.errorType, 'server_error');
    assert.equal(err.name, 'ShieldError');
  });

  it('AuthenticationError should extend ShieldError', () => {
    const err = new AuthenticationError('bad key');
    assert(err instanceof ShieldError);
    assert(err instanceof AuthenticationError);
    assert.equal(err.statusCode, 401);
    assert.equal(err.name, 'AuthenticationError');
  });

  it('RateLimitError should have limit/used/tier', () => {
    const err = new RateLimitError('too many requests', 100, 100, 'free');
    assert(err instanceof ShieldError);
    assert(err instanceof RateLimitError);
    assert.equal(err.statusCode, 429);
    assert.equal(err.limit, 100);
    assert.equal(err.used, 100);
    assert.equal(err.tier, 'free');
    assert.equal(err.name, 'RateLimitError');
  });

  it('ValidationError should extend ShieldError', () => {
    const err = new ValidationError('text too long');
    assert(err instanceof ShieldError);
    assert(err instanceof ValidationError);
    assert.equal(err.statusCode, 400);
    assert.equal(err.name, 'ValidationError');
  });
});

// ─── HTTP Integration Tests (mocked fetch) ───────────────────────

describe('Shield.scan() with mocked fetch', () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  it('should parse successful scan response', async () => {
    globalThis.fetch = mock.fn(async () => ({
      status: 200,
      json: async () => ({
        clean: false,
        risk_score: 8,
        severity: 'HIGH',
        findings_count: 1,
        findings: [
          {
            pattern_name: 'Instruction Override',
            severity: 'HIGH',
            category: 'prompt_injection',
            matched_text: 'ignore previous instructions',
            line_number: 1,
            description: 'Override attempt detected',
          },
        ],
        scan_time_ms: 5,
      }),
    }));

    const shield = new Shield('cgs_test_key');
    const result = await shield.scan('Ignore previous instructions');

    assert.equal(result.clean, false);
    assert.equal(result.riskScore, 8);
    assert.equal(result.severity, 'HIGH');
    assert.equal(result.findingsCount, 1);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].patternName, 'Instruction Override');
    assert.equal(result.findings[0].category, 'prompt_injection');
    assert.equal(result.scanTimeMs, 5);

    globalThis.fetch = originalFetch;
  });

  it('should parse clean scan response', async () => {
    globalThis.fetch = mock.fn(async () => ({
      status: 200,
      json: async () => ({
        clean: true,
        risk_score: 0,
        severity: 'CLEAN',
        findings_count: 0,
        findings: [],
        scan_time_ms: 3,
      }),
    }));

    const shield = new Shield('cgs_test_key');
    const result = await shield.scan('Hello, how are you?');

    assert.equal(result.clean, true);
    assert.equal(result.isSafe, true);
    assert.equal(result.riskScore, 0);
    assert.equal(result.findingsCount, 0);

    globalThis.fetch = originalFetch;
  });

  it('should send correct headers', async () => {
    let capturedHeaders;
    globalThis.fetch = mock.fn(async (url, opts) => {
      capturedHeaders = opts.headers;
      return {
        status: 200,
        json: async () => ({ clean: true, risk_score: 0, severity: 'CLEAN', findings_count: 0 }),
      };
    });

    const shield = new Shield('cgs_my_api_key_123');
    await shield.scan('test');

    assert.equal(capturedHeaders['X-API-Key'], 'cgs_my_api_key_123');
    assert.equal(capturedHeaders['Content-Type'], 'application/json');
    assert(capturedHeaders['User-Agent'].includes('clawguard-shield-js'));

    globalThis.fetch = originalFetch;
  });

  it('should send correct body', async () => {
    let capturedBody;
    globalThis.fetch = mock.fn(async (url, opts) => {
      capturedBody = JSON.parse(opts.body);
      return {
        status: 200,
        json: async () => ({ clean: true, risk_score: 0, severity: 'CLEAN', findings_count: 0 }),
      };
    });

    const shield = new Shield('cgs_test');
    await shield.scan('test input', 'custom-source');

    assert.equal(capturedBody.text, 'test input');
    assert.equal(capturedBody.source, 'custom-source');

    globalThis.fetch = originalFetch;
  });

  it('should throw AuthenticationError on 401', async () => {
    globalThis.fetch = mock.fn(async () => ({
      status: 401,
      json: async () => ({ message: 'Invalid API key' }),
    }));

    const shield = new Shield('cgs_test');
    await assert.rejects(
      () => shield.scan('test'),
      (err) => {
        assert(err instanceof AuthenticationError);
        assert.equal(err.message, 'Invalid API key');
        return true;
      }
    );

    globalThis.fetch = originalFetch;
  });

  it('should throw RateLimitError on 429', async () => {
    globalThis.fetch = mock.fn(async () => ({
      status: 429,
      json: async () => ({
        message: 'Rate limit exceeded',
        limit: 100,
        used: 100,
        tier: 'free',
      }),
    }));

    const shield = new Shield('cgs_test');
    await assert.rejects(
      () => shield.scan('test'),
      (err) => {
        assert(err instanceof RateLimitError);
        assert.equal(err.limit, 100);
        assert.equal(err.used, 100);
        assert.equal(err.tier, 'free');
        return true;
      }
    );

    globalThis.fetch = originalFetch;
  });

  it('should throw ValidationError on 400', async () => {
    globalThis.fetch = mock.fn(async () => ({
      status: 400,
      json: async () => ({ message: 'Text is required' }),
    }));

    const shield = new Shield('cgs_test');
    await assert.rejects(
      () => shield.scan(''),
      (err) => {
        assert(err instanceof ValidationError);
        assert.equal(err.message, 'Text is required');
        return true;
      }
    );

    globalThis.fetch = originalFetch;
  });

  it('should throw ShieldError on 500', async () => {
    globalThis.fetch = mock.fn(async () => ({
      status: 500,
      json: async () => ({ message: 'Internal server error' }),
    }));

    const shield = new Shield('cgs_test');
    await assert.rejects(
      () => shield.scan('test'),
      (err) => {
        assert(err instanceof ShieldError);
        assert.equal(err.statusCode, 500);
        return true;
      }
    );

    globalThis.fetch = originalFetch;
  });

  it('should handle network errors', async () => {
    globalThis.fetch = mock.fn(async () => {
      throw new TypeError('fetch failed');
    });

    const shield = new Shield('cgs_test');
    await assert.rejects(
      () => shield.scan('test'),
      (err) => {
        assert(err instanceof ShieldError);
        assert(err.message.includes('Cannot connect'));
        return true;
      }
    );

    globalThis.fetch = originalFetch;
  });
});

describe('Shield.scanBatch()', () => {
  it('should scan multiple texts', async () => {
    let callCount = 0;
    globalThis.fetch = mock.fn(async () => {
      callCount++;
      return {
        status: 200,
        json: async () => ({
          clean: callCount === 2,
          risk_score: callCount === 2 ? 0 : 8,
          severity: callCount === 2 ? 'CLEAN' : 'HIGH',
          findings_count: callCount === 2 ? 0 : 1,
          findings: callCount === 2
            ? []
            : [{ pattern_name: 'Test', severity: 'HIGH', category: 'pi', matched_text: 'x' }],
        }),
      };
    });

    const shield = new Shield('cgs_test');
    const results = await shield.scanBatch(['attack text', 'safe text', 'another attack']);

    assert.equal(results.length, 3);
    assert(results[0] instanceof ScanResult);

    globalThis.fetch = undefined;
  });
});

describe('Shield.health()', () => {
  it('should return health status without auth', async () => {
    globalThis.fetch = mock.fn(async (url) => {
      assert(url.endsWith('/health'));
      return {
        status: 200,
        json: async () => ({
          status: 'healthy',
          version: '1.0.0',
          patterns_count: 42,
        }),
      };
    });

    const shield = new Shield('cgs_test');
    const health = await shield.health();

    assert.equal(health.status, 'healthy');
    assert.equal(health.patterns_count, 42);

    // Verify no API key header sent
    const fetchCall = globalThis.fetch.mock.calls[0];
    assert.equal(fetchCall.arguments[1].headers, undefined);

    globalThis.fetch = undefined;
  });
});

describe('Shield.usage()', () => {
  it('should parse usage response', async () => {
    globalThis.fetch = mock.fn(async () => ({
      status: 200,
      json: async () => ({
        tier: 'free',
        tier_name: 'Free',
        daily_limit: 100,
        today_used: 42,
        today_remaining: 58,
        last_30_days: {
          total_requests: 1000,
          total_findings: 250,
          avg_response_time_ms: 6.5,
        },
      }),
    }));

    const shield = new Shield('cgs_test');
    const usage = await shield.usage();

    assert(usage instanceof UsageStats);
    assert.equal(usage.tier, 'free');
    assert.equal(usage.tierName, 'Free');
    assert.equal(usage.dailyLimit, 100);
    assert.equal(usage.todayUsed, 42);
    assert.equal(usage.todayRemaining, 58);
    assert.equal(usage.totalRequests, 1000);
    assert.equal(usage.totalFindings, 250);
    assert.equal(usage.avgResponseTimeMs, 6.5);

    globalThis.fetch = undefined;
  });
});

describe('Shield.patterns()', () => {
  it('should return patterns data', async () => {
    globalThis.fetch = mock.fn(async () => ({
      status: 200,
      json: async () => ({
        total_patterns: 42,
        categories: {
          prompt_injection: 15,
          data_exfiltration: 8,
          code_obfuscation: 7,
          command_injection: 6,
          social_engineering: 6,
        },
      }),
    }));

    const shield = new Shield('cgs_test');
    const patterns = await shield.patterns();

    assert.equal(patterns.total_patterns, 42);
    assert.equal(Object.keys(patterns.categories).length, 5);

    globalThis.fetch = undefined;
  });
});
