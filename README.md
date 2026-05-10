# @tailsec/scan-deps

Security scanner for npm dependencies. Detects malicious packages, known vulnerabilities, and problematic licenses.

## Usage

```bash
npx @tailsec/scan-deps ./package.json
npx @tailsec/scan-deps ./package.json --format json
```

## Checks

- Malicious packages (event-stream, left-pad, etc.)
- Known vulnerabilities (glob <8.1.0, tar <6.1.13, etc.)
- Banned licenses (GPL-3.0, AGPL-3.0, SSPL-1.0, etc.)
- Copyleft licenses (GPL-2.0, MPL, CDDL, etc.)