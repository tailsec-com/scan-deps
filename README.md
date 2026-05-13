# @tailsec/scan-deps

Security scanner for npm dependencies. Detects malicious packages, known vulnerabilities, and problematic licenses in package.json dependencies.

[![npm](https://img.shields.io/npm/v/@tailsec/scan-deps)](https://www.npmjs.com/package/@tailsec/scan-deps)
[![CI](https://github.com/tailsec-com/scan-deps/actions/workflows/ci.yml/badge.svg)](https://github.com/tailsec-com/scan-deps)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

## Features

- Detects malicious packages (event-stream, left-pad, etc.)
- Checks for known vulnerabilities with CVE references
- Identifies banned and copyleft licenses
- Scans dependencies, devDependencies, peerDependencies, optionalDependencies
- JSON output for CI/CD integration
- No external dependencies

## Installation

```bash
npm install -g @tailsec/scan-deps
```

## Usage

```bash
# Scan a package.json file
npx @tailsec/scan-deps ./package.json

# Output as JSON
npx @tailsec/scan-deps ./package.json --format json
```

### Programmatic

```typescript
import { scanDeps, formatDepsOutput } from '@tailsec/scan-deps';

const findings = scanDeps('./package.json');
console.log(formatDepsOutput(findings, 'text'));
console.log(formatDepsOutput(findings, 'json'));
```

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `text` | Output format: `text` or `json` |

## Supported File Types

| File | Format |
|------|--------|
| package.json | JSON |

## Detection Rules

### Malicious / Deprecated Packages

| Package | Severity | Issue |
|---------|----------|-------|
| event-stream <3.3.6 | Critical | Malicious code injected via flatmap-stream |
| left-pad | Critical | Package removed from npm — supply chain risk |
| node-uuid | Critical | Deprecated — use uuid package |
| request | Critical | Deprecated — no security patches since 2020 |
| moment | Critical | Deprecated — no security patches |
| blamer | Critical | Malicious — steals git credentials |
| eslint-scope <3.7.2 | Critical | Brute-force git tokens from .npmrc |

### Known Vulnerabilities

| Package | Severity | Fixed Version |
|---------|----------|--------------|
| glob <8.1.0 | High | 8.1.0 |
| tar <6.1.13 | High | 6.1.13 |
| postcss <8.4.31 | High | 8.4.31 |
| semver <7.5.2 | High | 7.5.2 |
| json5 <1.0.2 | High | 1.0.2 |
| node-fetch <2.6.13 | High | 2.6.13 |
| ua-parser-js <0.7.31 | High | 0.7.31 |
| ansi-regex <5.0.1 | High | 5.0.1 |
| js-yaml <5.1.0 | High | 5.1.0 |
| yaml <2.2.2 | High | 2.2.2 |
| express <4.19.2 | High | 4.19.2 |
| fast-xml-parser <4.2.5 | High | 4.2.5 |
| ws <8.17.1 | High | 8.17.1 |
| cookie <0.7.1 | High | 0.7.1 |
| body-parser <1.20.3 | High | 1.20.3 |

### Banned Licenses

| License | Severity | Issue |
|---------|----------|-------|
| GPL-3.0 | High | Banned — strong copyleft |
| AGPL-3.0 | High | Banned — strong copyleft |
| LGPL-3.0 | High | Banned — weak copyleft |
| SSPL-1.0 | High | Banned — server-side copyleft |
| CC-BY-NC-4.0 | High | Banned — non-commercial |
| Unlicense | High | Banned — public domain |
| WTFPL | High | Banned — public domain |

### Copyleft Licenses (Warning)

| License | Severity | Issue |
|---------|----------|-------|
| GPL-2.0 | Medium | Copyleft — may require GPL linking |
| MPL-2.0 | Medium | Copyleft — file-level share-alike |
| CDDL-1.0 | Medium | Copyleft — header-level share-alike |
| EPL-2.0 | Medium | Copyleft — weak copyleft |
| OSL-3.0 | Medium | Copyleft — strong copyleft |

## Exit Codes

- `0` — Scan completed, no issues found
- `1` — Scan completed, issues found
- `2` — Scan failed (file errors, parse errors)

## Contributing

Rules are defined in `src/deps.ts`:

- **Malicious/deprecated packages**: `CRITICAL_DEPS` Map
- **Known vulnerabilities**: `KNOWN_VULNERABLE` Map
- **Banned licenses**: `LICENSE_BANNED` Set
- **Warning licenses**: `LICENSE_WARN` Set

To add a new malicious package:

```typescript
['new-package-name', { ver: '<1.2.3', reason: 'Description of the issue' }],
```

To add a known vulnerability:

```typescript
['package-name', '<1.2.3'],
```

To add a banned license:

```typescript
'NEW-LICENSE',
```

## License

MIT