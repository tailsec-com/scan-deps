import { scanDeps, formatDepsOutput } from './deps.js';

const args = process.argv.slice(2);
const packageJsonPath = args[0];

if (!packageJsonPath) {
  console.error('Usage: tailsec-scan-deps <path-to-package.json> [--format json]');
  process.exit(1);
}

const formatArg = args.includes('--format') && args[args.indexOf('--format') + 1] === 'json' ? 'json' : 'text';

try {
  const findings = scanDeps(packageJsonPath);
  const output = formatDepsOutput(findings, formatArg);
  console.log(output);
} catch (err) {
  console.error(`Error scanning ${packageJsonPath}:`, err instanceof Error ? err.message : err);
  process.exit(1);
}