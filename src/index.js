/**
 * ClawGuard Shield API Client
 *
 * A lightweight, zero-dependency JavaScript client for the ClawGuard Shield API.
 * Detects prompt injection, data exfiltration, and 40+ attack patterns in under 10ms.
 *
 * @example
 * const { Shield } = require('clawguard-shield');
 * const shield = new Shield('cgs_your_key');
 * const result = await shield.scan('Ignore all previous instructions');
 * console.log(result.clean); // false
 */

'use strict';

// ─── Error Classes ───────────────────────────────────────────────

class ShieldError extends Error {
  /**
   * @param {string} message
   * @param {number} [statusCode=0]
   * @param {string} [errorType='']
   */
  constructor(message, statusCode = 0, errorType = '') {
    super(message);
    this.name = 'ShieldError';
    this.statusCode = statusCode;
    this.errorType = errorType;
  }
}

class AuthenticationError extends ShieldError {
  constructor(message, statusCode = 401) {
    super(message, statusCode, 'authentication_error');
    this.name = 'AuthenticationError';
  }
}

class RateLimitError extends ShieldError {
  /**
   * @param {string} message
   * @param {number} [limit=0]
   * @param {number} [used=0]
   * @param {string} [tier='']
   */
  constructor(message, limit = 0, used = 0, tier = '') {
    super(message, 429, 'rate_limit_exceeded');
    this.name = 'RateLimitError';
    this.limit = limit;
    this.used = used;
    this.tier = tier;
  }
}

class ValidationError extends ShieldError {
  constructor(message) {
    super(message, 400, 'validation_error');
    this.name = 'ValidationError';
  }
}

// ─── Data Classes ────────────────────────────────────────────────

class Finding {
  /**
   * A single security finding from a scan.
   *
   * @param {object} data
   * @param {string} data.patternName
   * @param {string} data.severity
   * @param {string} data.category
   * @param {string} data.matchedText
   * @param {number} [data.lineNumber=0]
   * @param {string} [data.description='']
   */
  constructor({ patternName, severity, category, matchedText, lineNumber = 0, description = '' }) {
    this.patternName = patternName;
    this.severity = severity;
    this.category = category;
    this.matchedText = matchedText;
    this.lineNumber = lineNumber;
    this.description = description;
  }

  toString() {
    return `Finding(${this.severity}: ${this.patternName})`;
  }

  /**
   * Convert to plain object.
   * @returns {object}
   */
  toJSON() {
    return {
      patternName: this.patternName,
      severity: this.severity,
      category: this.category,
      matchedText: this.matchedText,
      lineNumber: this.lineNumber,
      description: this.description,
    };
  }
}

class ScanResult {
  /**
   * Result of a security scan.
   *
   * @param {object} data
   * @param {boolean} data.clean
   * @param {number} data.riskScore
   * @param {string} data.severity
   * @param {number} data.findingsCount
   * @param {Finding[]} [data.findings=[]]
   * @param {number} [data.scanTimeMs=0]
   */
  constructor({ clean, riskScore, severity, findingsCount, findings = [], scanTimeMs = 0 }) {
    this.clean = clean;
    this.riskScore = riskScore;
    this.severity = severity;
    this.findingsCount = findingsCount;
    this.findings = findings;
    this.scanTimeMs = scanTimeMs;
  }

  /** Alias for clean — returns true if no threats found. */
  get isSafe() {
    return this.clean;
  }

  /** Returns true if severity is CRITICAL. */
  get isCritical() {
    return this.severity === 'CRITICAL';
  }

  toString() {
    const status = this.clean
      ? 'CLEAN'
      : `${this.severity} (${this.findingsCount} findings)`;
    return `ScanResult(${status}, risk=${this.riskScore}/10, ${this.scanTimeMs}ms)`;
  }

  toJSON() {
    return {
      clean: this.clean,
      riskScore: this.riskScore,
      severity: this.severity,
      findingsCount: this.findingsCount,
      findings: this.findings.map(f => f.toJSON()),
      scanTimeMs: this.scanTimeMs,
    };
  }
}

class UsageStats {
  /**
   * API usage statistics.
   *
   * @param {object} data
   * @param {string} data.tier
   * @param {string} data.tierName
   * @param {number|string} data.dailyLimit
   * @param {number} data.todayUsed
   * @param {number|string} data.todayRemaining
   * @param {number} [data.totalRequests=0]
   * @param {number} [data.totalFindings=0]
   * @param {number} [data.avgResponseTimeMs=0]
   */
  constructor({
    tier,
    tierName,
    dailyLimit,
    todayUsed,
    todayRemaining,
    totalRequests = 0,
    totalFindings = 0,
    avgResponseTimeMs = 0,
  }) {
    this.tier = tier;
    this.tierName = tierName;
    this.dailyLimit = dailyLimit;
    this.todayUsed = todayUsed;
    this.todayRemaining = todayRemaining;
    this.totalRequests = totalRequests;
    this.totalFindings = totalFindings;
    this.avgResponseTimeMs = avgResponseTimeMs;
  }

  toString() {
    return `UsageStats(${this.tierName}: ${this.todayUsed}/${this.dailyLimit} today)`;
  }
}

// ─── Shield Client ───────────────────────────────────────────────

class Shield {
  /**
   * ClawGuard Shield API client.
   *
   * @param {string} apiKey - Your Shield API key (starts with 'cgs_').
   * @param {object} [options]
   * @param {string} [options.baseUrl='https://prompttools.co/api/v1'] - API base URL.
   * @param {number} [options.timeout=10000] - Request timeout in milliseconds.
   *
   * @example
   * const shield = new Shield('cgs_your_key');
   * const result = await shield.scan('Ignore all previous instructions');
   * console.log(result.clean);    // false
   * console.log(result.riskScore); // 10
   */
  constructor(apiKey, options = {}) {
    if (!apiKey) {
      throw new AuthenticationError('API key is required.');
    }
    if (!apiKey.startsWith('cgs_')) {
      throw new AuthenticationError("Invalid API key format. Keys start with 'cgs_'.");
    }

    this.apiKey = apiKey;
    this.baseUrl = (options.baseUrl || Shield.DEFAULT_URL).replace(/\/+$/, '');
    this.timeout = options.timeout || 10000;
  }

  /**
   * Scan text for security threats.
   *
   * @param {string} text - The text to scan.
   * @param {string} [source='sdk'] - Source identifier.
   * @returns {Promise<ScanResult>}
   *
   * @example
   * const result = await shield.scan('Ignore all previous instructions');
   * if (!result.clean) {
   *   console.log(`Risk: ${result.riskScore}/10`);
   * }
   */
  async scan(text, source = 'sdk') {
    const data = await this._request('POST', '/scan', {
      body: JSON.stringify({ text, source }),
    });

    const findings = (data.findings || []).map(
      (f) =>
        new Finding({
          patternName: f.pattern_name || '',
          severity: f.severity || '',
          category: f.category || '',
          matchedText: f.matched_text || '',
          lineNumber: f.line_number || 0,
          description: f.description || '',
        })
    );

    return new ScanResult({
      clean: data.clean ?? true,
      riskScore: data.risk_score ?? 0,
      severity: data.severity ?? 'CLEAN',
      findingsCount: data.findings_count ?? 0,
      findings,
      scanTimeMs: data.scan_time_ms ?? 0,
    });
  }

  /**
   * Scan multiple texts. Convenience method that calls scan() for each.
   *
   * @param {string[]} texts - Array of texts to scan.
   * @param {string} [source='sdk'] - Source identifier.
   * @returns {Promise<ScanResult[]>}
   */
  async scanBatch(texts, source = 'sdk') {
    return Promise.all(texts.map((text) => this.scan(text, source)));
  }

  /**
   * Check API health status (no auth required).
   *
   * @returns {Promise<object>} - { status, version, patterns_count }
   */
  async health() {
    const url = `${this.baseUrl}/health`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
      });
      return await resp.json();
    } catch (err) {
      if (err.name === 'AbortError') {
        throw new ShieldError(`Request timed out after ${this.timeout}ms.`);
      }
      throw new ShieldError(`Cannot connect to Shield API: ${err.message}`);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * List all detection patterns.
   *
   * @returns {Promise<object>} - { total_patterns, categories }
   */
  async patterns() {
    return this._request('GET', '/patterns');
  }

  /**
   * Get your API usage statistics.
   *
   * @returns {Promise<UsageStats>}
   */
  async usage() {
    const data = await this._request('GET', '/usage');
    const last30 = data.last_30_days || {};

    return new UsageStats({
      tier: data.tier || 'free',
      tierName: data.tier_name || 'Free',
      dailyLimit: data.daily_limit ?? 100,
      todayUsed: data.today_used ?? 0,
      todayRemaining: data.today_remaining ?? 100,
      totalRequests: last30.total_requests ?? 0,
      totalFindings: last30.total_findings ?? 0,
      avgResponseTimeMs: last30.avg_response_time_ms ?? 0,
    });
  }

  /**
   * Make an authenticated API request.
   * @private
   */
  async _request(method, path, options = {}) {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    const headers = {
      'X-API-Key': this.apiKey,
      'Content-Type': 'application/json',
      'User-Agent': `clawguard-shield-js/0.1.0`,
      ...(options.headers || {}),
    };

    let resp;
    try {
      resp = await fetch(url, {
        method,
        headers,
        body: options.body,
        signal: controller.signal,
      });
    } catch (err) {
      if (err.name === 'AbortError') {
        throw new ShieldError(`Request timed out after ${this.timeout}ms.`);
      }
      throw new ShieldError(`Cannot connect to Shield API: ${err.message}`);
    } finally {
      clearTimeout(timeoutId);
    }

    if (resp.status === 200 || resp.status === 201) {
      return resp.json();
    }

    // Handle errors
    let data, message, errorType;
    try {
      data = await resp.json();
      message = data.message || 'Unknown error';
      errorType = data.error || '';
    } catch {
      message = `HTTP ${resp.status}`;
      errorType = '';
      data = {};
    }

    if (resp.status === 401 || resp.status === 403) {
      throw new AuthenticationError(message, resp.status);
    }
    if (resp.status === 429) {
      throw new RateLimitError(
        message,
        data.limit || 0,
        data.used || 0,
        data.tier || ''
      );
    }
    if (resp.status === 400) {
      throw new ValidationError(message);
    }
    throw new ShieldError(message, resp.status, errorType);
  }

  toString() {
    const prefix = this.apiKey.slice(0, 12) + '...';
    return `Shield(key=${prefix}, url=${this.baseUrl})`;
  }
}

/** Default API URL */
Shield.DEFAULT_URL = 'https://prompttools.co/api/v1';

// ─── Exports ─────────────────────────────────────────────────────

module.exports = {
  Shield,
  ShieldError,
  AuthenticationError,
  RateLimitError,
  ValidationError,
  Finding,
  ScanResult,
  UsageStats,
};
