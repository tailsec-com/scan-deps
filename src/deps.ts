import { readFileSync } from 'fs';

export interface DepFinding {
  ruleId: string;
  type: string;
  severity: string;
  title: string;
  package: string;
  currentVersion?: string;
  fixedVersion?: string;
  cve?: string;
  advice: string[];
}

const CRITICAL_DEPS = [
  { pkg: 'event-stream', ver: '<3.3.6', reason: 'Malicious code injected via event-stream flatmap-stream dependency' },
  { pkg: 'left-pad', ver: '<1.3.0', reason: 'Package removed from npm — potential supply chain risk' },
  { pkg: 'node-uuid', ver: 'any', reason: 'Deprecated — use uuid package instead' },
  { pkg: 'request', ver: 'any', reason: 'Deprecated — no security patches since 2020' },
  { pkg: 'moment', ver: 'any', reason: 'Deprecated — use date-fns or luxon as successor has no security patches' },
  { pkg: 'lodash', ver: '<4.17.21', reason: 'Prototype pollution vulnerabilities (CVE-2021-23337, CVE-2020-8203)' },
  { pkg: 'underscore', ver: '<1.13.0', reason: 'Prototype pollution and XSS vulnerabilities' },
  { pkg: 'minimist', ver: '<1.2.6', reason: 'Prototype pollution (CVE-2021-44906)' },
  { pkg: 'handlebars', ver: '<4.7.7', reason: 'RCE via prototype pollution (CVE-2021-23369)' },
  { pkg: 'blamer', ver: 'any', reason: 'Malicious package — steals git credentials' },
  { pkg: 'ppth拔', ver: 'any', reason: 'Malicious package — typosquatting of pptx-genjs' },
  { pkg: 'eslint-scope', ver: '<3.7.2', reason: 'Brute-force git tokens from .npmrc (CVE-2018-16469)' },
];

const KNOWN_VULNERABLE = new Map([
  ['glob', '<8.1.0'],
  ['tar', '<6.1.13'],
  ['postcss', '<8.4.31'],
  ['semver', '<7.5.2'],
  ['json5', '<1.0.2'],
  ['loader-utils', '<1.4.2'],
  ['node-fetch', '<2.6.13'],
  ['nth-check', '<2.1.1'],
  ['word-wrap', '<1.2.5'],
  ['cookie', '<0.5.0'],
  ['ua-parser-js', '<0.7.31'],
  ['ansi-regex', '<5.0.1'],
  ['path-parse', '<1.0.7'],
  ['shell-quote', '<1.7.3'],
  ['js-yaml', '<5.1.0'],
  ['yaml', '<2.2.2'],
]);

const LICENSE_BANNED = new Set([
  'GPL-3.0', 'AGPL-3.0', 'LGPL-3.0',
  'CC-BY-NC-4.0', 'CC-BY-NC-ND-4.0',
  'Unlicense', 'WTFPL', 'SSPL-1.0',
]);

const LICENSE_WARN = new Set([
  'GPL-2.0', 'GPL-3.0',
  'LGPL-2.1', 'LGPL-3.0',
  'MPL-2.0', 'MPL-1.1',
  'CDDL-1.0', 'EPL-1.0', 'EPL-2.0',
  'OSL-3.0', 'EUPL-1.2',
]);

function findDeps(packageJsonPath: string): Array<{ name: string; version: string }> {
  try {
    const content = readFileSync(packageJsonPath, 'utf-8');
    const pkg = JSON.parse(content);
    const deps: Array<{ name: string; version: string }> = [];

    const all: Record<string, string> = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
      ...pkg.peerDependencies,
      ...pkg.optionalDependencies,
    };

    for (const [name, version] of Object.entries(all)) {
      deps.push({ name, version: String(version).replace(/^[\^~>=<]+/, '') });
    }
    return deps;
  } catch {
    return [];
  }
}

function checkCriticalDeps(deps: Array<{ name: string; version: string }>): DepFinding[] {
  const findings: DepFinding[] = [];
  for (const dep of deps) {
    for (const crit of CRITICAL_DEPS) {
      if (crit.pkg === dep.name) {
        findings.push({
          ruleId: `critical-dep-${dep.name.replace('/', '-')}`,
          type: 'dependency',
          severity: 'critical',
          title: `Critical/trivial dependency: ${dep.name}`,
          package: dep.name,
          currentVersion: dep.version,
          advice: [crit.reason, 'Remove or replace this package immediately'],
        });
      }
    }
  }
  return findings;
}

function checkKnownVulns(deps: Array<{ name: string; version: string }>): DepFinding[] {
  const findings: DepFinding[] = [];
  for (const dep of deps) {
    const range = KNOWN_VULNERABLE.get(dep.name);
    if (range) {
      findings.push({
        ruleId: `known-vuln-${dep.name.replace('/', '-')}`,
        type: 'dependency',
        severity: 'high',
        title: `Known vulnerable dependency: ${dep.name}@${dep.version}`,
        package: dep.name,
        currentVersion: dep.version,
        fixedVersion: range,
        advice: [`Upgrade to ${range} or later`],
      });
    }
  }
  return findings;
}

function checkLicenses(deps: Array<{ name: string; version: string }>): DepFinding[] {
  const findings: DepFinding[] = [];
  for (const dep of deps) {
    for (const bad of LICENSE_BANNED) {
      if (dep.version.includes(bad)) {
        findings.push({
          ruleId: `banned-license-${dep.name.replace('/', '-')}`,
          type: 'license',
          severity: 'high',
          title: `Banned license ${bad} in ${dep.name}`,
          package: dep.name,
          currentVersion: dep.version,
          advice: [`${bad} is not allowed in this project`, 'Find an alternative package with permissive license'],
        });
      }
    }
    for (const warn of LICENSE_WARN) {
      if (dep.version.includes(warn)) {
        findings.push({
          ruleId: `copyleft-license-${dep.name.replace('/', '-')}`,
          type: 'license',
          severity: 'medium',
          title: `Copyleft license ${warn} in ${dep.name} — may have GPL implications`,
          package: dep.name,
          currentVersion: dep.version,
          advice: ['Review license obligations', 'Consider permissive alternatives'],
        });
      }
    }
  }
  return findings;
}

export function scanDeps(packageJsonPath: string): DepFinding[] {
  const deps = findDeps(packageJsonPath);
  const allFindings: DepFinding[] = [];

  allFindings.push(...checkCriticalDeps(deps));
  allFindings.push(...checkKnownVulns(deps));
  allFindings.push(...checkLicenses(deps));

  return allFindings;
}

export function formatDepsOutput(findings: DepFinding[], format: 'text' | 'json' = 'text'): string {
  if (format === 'json') {
    return JSON.stringify({ dependencies: findings, total: findings.length }, null, 2);
  }

  const lines: string[] = ['\n=== Dependency Findings ===\n'];

  const byType = { dependency: 0, license: 0 };
  for (const f of findings) byType[f.type as keyof typeof byType]++;

  lines.push(`Total: ${findings.length} issues (${byType.dependency} vulnerabilities, ${byType.license} license issues)\n`);
  lines.push('─'.repeat(60));

  for (const f of findings) {
    lines.push(`\n[${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`  Package: ${f.package}${f.currentVersion ? `@${f.currentVersion}` : ''}`);
    if (f.fixedVersion) lines.push(`  Fixed: ${f.fixedVersion}`);
    if (f.advice.length > 0) lines.push(`  ${f.advice.join(' | ')}`);
  }

  return lines.join('\n');
}