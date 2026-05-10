#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { glob } from 'glob';
import { scanDeps, formatDepsOutput } from './detectors/deps.ts';

function help() {
  console.log(`Tailsec Deps Scanner v0.1.0

Usage: npx @tailsec/scan-deps [options] [path]

Options:
  -f, --format   text (default) or json
  -o, --output   Write to file
  -h, --help     Show help
`);
}

async function main() {
  const { values: args, positionals } = parseArgs({
    args: Bun.argv,
    options: {
      'format': { type: 'string', default: 'text', short: 'f' },
      'output': { type: 'string', short: 'o' },
      'help': { type: 'boolean', short: 'h' },
    },
    allowPositionals: true,
  });
  if (args.help) { help(); process.exit(0); }

  const target = positionals[0] || '.';
  const format = args.format || 'text';
  const output = args.output;

  const pkgFiles = await glob('**/package.json', { cwd: target, absolute: true, ignore: ['**/node_modules/**'] });

  const allFindings = [];
  for (const pkg of pkgFiles) {
    const findings = scanDeps(pkg);
    allFindings.push(...findings.map(f => ({ ...f, file: pkg })));
  }

  const str = formatDepsOutput(allFindings, format as 'text' | 'json');
  if (output) { await Bun.write(output, str); console.log(`Wrote to ${output}`); }
  else console.log(str);
}

main().catch(console.error);