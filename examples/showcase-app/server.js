/**
 * ClawGuard Shield — Interactive Demo App
 *
 * A visual showcase that lets you type text and see prompt injection
 * detection results in real time. Perfect for demos and screenshots.
 *
 * Usage:
 *   CLAWGUARD_API_KEY=cgs_your_key npm start
 *   # or: CLAWGUARD_API_KEY=cgs_your_key node server.js
 *
 * Then open http://localhost:3000
 */

const express = require('express');
const path = require('path');
const { Shield, ShieldError } = require('clawguard-shield');

const app = express();
app.use(express.json());

const apiKey = process.env.CLAWGUARD_API_KEY;
if (!apiKey) {
  console.error('ERROR: Set CLAWGUARD_API_KEY environment variable');
  console.error('  Get a free key at https://prompttools.co');
  process.exit(1);
}

const shield = new Shield(apiKey);

// Serve static HTML
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Scan endpoint
app.post('/api/scan', async (req, res) => {
  const { text } = req.body;

  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: 'Text is required' });
  }

  try {
    const result = await shield.scan(text, 'showcase-app');

    res.json({
      clean: result.clean,
      riskScore: result.riskScore,
      severity: result.severity,
      findingsCount: result.findingsCount,
      scanTimeMs: result.scanTimeMs,
      findings: result.findings.map((f) => ({
        patternName: f.patternName,
        severity: f.severity,
        category: f.category,
        matchedText: f.matchedText,
        description: f.description,
      })),
    });
  } catch (err) {
    if (err instanceof ShieldError) {
      res.status(err.statusCode || 500).json({ error: err.message });
    } else {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});

// Health check
app.get('/api/health', async (req, res) => {
  try {
    const health = await shield.health();
    const usage = await shield.usage();
    res.json({ ...health, usage: { used: usage.todayUsed, limit: usage.dailyLimit, remaining: usage.todayRemaining } });
  } catch (err) {
    res.status(503).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  ClawGuard Shield Demo running at http://localhost:${PORT}\n`);
});
