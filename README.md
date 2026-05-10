# Tailscan — Code Security Scanner

Static analysis security scanner for JavaScript, TypeScript, Python, Java, PHP, C#, Go, Rust, and C/C++.

## Detects

| Category | Examples |
|----------|----------|
| **SQL Injection** | Template string interpolation, string concatenation, ORM misuse |
| **Cross-Site Scripting** | `innerHTML` assignment, `document.write`, reflected XSS |
| **Command Injection** | `exec()`, `spawn()`, `eval()`, shell commands with user input |
| **Path Traversal** | Unvalidated `readFile`, `path.join` with user input, Zip Slip |
| **Authentication** | JWT with `algorithm: none`, hardcoded passwords/keys, always-true checks |
| **Weak Cryptography** | MD5/SHA1 hashing, `Math.random()` for tokens, weak cipher modes |
| **Secrets** | API keys, tokens, credentials in code or Docker ENV |
| **Container Issues** | Running as root, missing tag, secrets in ENV, curl-pipe-sh |
| **Kubernetes** | Privileged containers, hostPath volumes, host network/PID/IPC |
| **Terraform** | Public S3 ACLs, IAM wildcard actions, public DBs, insecure SSL |

## Installation

```bash
npm install @tailsec/scan-code
# or
bun add @tailsec/scan-code
```

## Usage

```bash
# Scan a single file
npx tailsec-scan-code app.js

# Scan by glob pattern
npx tailsec-scan-code "src/**/*.ts"

# JSON output
npx tailsec-scan-code . --format json -o report.json

# SARIF for CI integration
npx tailsec-scan-code . --format sarif -o results.sarif

# Skip node_modules and test files
npx tailsec-scan-code . --skip "**/node_modules/**,**/*.test.ts"
```

## Output Formats

- **text** (default) — Human-readable table with severity, rule ID, file:line, and code snippet
- **json** — Structured JSON with full finding details and scan statistics
- **sarif** — SARIF 2.1.0 for integration with GitHub Security, CodeQL, Semgrep, etc.

## Programmatic API

```typescript
import { scanPaths } from '@tailsec/scan-code';

// Scan files matching patterns
const results = await scanPaths(['src/**/*.ts', 'lib/**/*.js']);

// Each result contains file, language, findings, and stats
for (const result of results) {
  console.log(`${result.file}: ${result.findings.length} issues`);
}
```

## As a Library

```typescript
import { detectSQLInjection, detectXSS, detectCommandInjection } from '@tailsec/scan-code';

const sqlIssues = detectSQLInjection(code, 'javascript');
const xssIssues = detectXSS(code, 'typescript');
const cmdIssues = detectCommandInjection(code, 'javascript');
```

## Configuration

The scanner automatically skips:
- `node_modules/`, `.git/`, `dist/`, `build/`, `coverage/`
- `*.test.ts`, `*.spec.ts`, `*.test.js`, `*.spec.js`
- Binary files: `*.min.js`, `*.map`, `*.jpg`, `*.png`, `*.woff`

Use `--skip` to add additional patterns:
```bash
tailsec-scan-code . --skip "**/vendor/**,**/.next/**"
```

## Severity Levels

- **Critical** — Immediate security risk (SQLi, command injection, exposed secrets)
- **High** — Significant vulnerability (XSS, weak crypto, hardcoded credentials)
- **Medium** — Moderate risk (insecure config, missing security headers)
- **Low** — Minor issue or best-practice violation

## Exit Codes

- `0` — Scan complete (findings don't affect exit code)
- `1` — Fatal error (file not found, invalid args)

## Related Tools

| Tool | Scope |
|------|-------|
| `@tailsec/scan-secrets` | Dedicated secrets scanner with 35+ patterns |
| `@tailsec/scan-container` | Dockerfile and container image scanning |
| `@tailsec/scan-k8s` | Kubernetes manifest auditing |
| `@tailsec/scan-terraform` | IaC scanning for AWS/Azure/GCP |
| `@tailsec/scan-deps` | Dependency vulnerability checking |
| `@tailsec/scan-license` | License compliance scanning |

## License

MIT