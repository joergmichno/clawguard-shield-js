# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in ClawGuard Shield, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email **michno.jrg@gmail.com** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
3. You will receive an acknowledgment within 48 hours
4. We aim to release a fix within 7 days for critical issues

## Security Measures

- Zero runtime dependencies (only native `fetch`)
- API key validation at constructor time
- Request timeout protection (AbortController)
- No eval(), no dynamic code execution
- All inputs sanitized before API transmission

## Scope

This policy covers:
- The `clawguard-shield` npm package
- The JavaScript SDK source code in this repository

For vulnerabilities in the Shield API itself, please report to the same email address.
