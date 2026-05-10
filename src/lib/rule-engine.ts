import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

export interface Rule {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  languages: string[];
  patterns: RulePattern[];
  sinks?: string[];
  sources?: string[];
  sanitizers?: string[];
  remediations: string[];
  cwe?: string;
  owasp?: string[];
  references?: string[];
}

export interface RulePattern {
  kind: string;
  match: string;
  context?: Record<string, unknown>;
  interpolated?: boolean;
}

export interface RuleSet {
  $schema?: string;
  version: string;
  name: string;
  description: string;
  rules: Rule[];
}

export interface RuleMatch {
  ruleId: string;
  type: string;
  severity: string;
  title: string;
  line: number;
  column: number;
  matchedText: string;
  code: string;
  cwe?: string;
  remediation?: string[];
}

export interface RuleEngineResult {
  ruleId: string;
  matches: RuleMatch[];
}

const RULE_DIR = dirname(fileURLToPath(import.meta.url));

function getRulesDir(): string {
  const libDir = RULE_DIR;
  const srcDir = join(libDir, '..');
  return join(srcDir, 'rules');
}

export function loadRuleSet(name: string): RuleSet {
  const content = readFileSync(join(getRulesDir(), `${name}.rules.json`), 'utf-8');
  return JSON.parse(content) as RuleSet;
}

export function loadAllRuleSets(): Map<string, RuleSet> {
  const sets = new Map<string, RuleSet>();
  const rulesDir = getRulesDir();
  let files: string[];
  try {
    files = readdirSync(rulesDir).filter(f => f.endsWith('.rules.json'));
  } catch {
    return sets;
  }

  for (const file of files) {
    const name = file.replace('.rules.json', '');
    try {
      const set = loadRuleSet(name);
      sets.set(name, set);
    } catch {
      // skip invalid rule files
    }
  }

  return sets;
}

export function compilePattern(rule: Rule): RegExp | null {
  for (const p of rule.patterns) {
    if (p.kind === 'regex' || p.kind === 'call' || p.kind === 'assignment' || p.kind === 'string' || p.kind === 'template' || p.kind === 'directive' || p.kind === 'prop') {
      try {
        return new RegExp(p.match, 'gi');
      } catch {
        return null;
      }
    }
  }
  return null;
}

export function applyRules(content: string, lang: string, ruleSets?: Map<string, RuleSet>): RuleMatch[] {
  const sets = ruleSets || loadAllRuleSets();
  const matches: RuleMatch[] = [];
  const lines = content.split('\n');

  for (const [, ruleSet] of sets) {
    for (const rule of ruleSet.rules) {
      if (rule.languages[0] !== '*' && !rule.languages.includes(lang)) continue;

      const regex = compilePattern(rule);
      if (!regex) continue;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        regex.lastIndex = 0;
        const match = regex.exec(line);

        if (match) {
          const title = rule.id.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

          matches.push({
            ruleId: rule.id,
            type: rule.type,
            severity: rule.severity,
            title: `Rule: ${title}`,
            line: i + 1,
            column: match.index + 1,
            matchedText: match[0],
            code: line.trim(),
            cwe: rule.cwe,
            remediation: rule.remediations,
          });
        }
      }
    }
  }

  return matches;
}

export function formatRuleMatch(match: RuleMatch): string {
  const parts = [
    `[${match.severity.toUpperCase()}] ${match.title}`,
    `  File: line ${match.line}:${match.column}`,
    `  Match: ${match.matchedText}`,
    `  Code: ${match.code}`,
  ];

  if (match.cwe) parts.push(`  CWE: ${match.cwe}`);
  if (match.remediation) parts.push(`  Fix: ${match.remediation.join(' | ')}`);

  return parts.join('\n');
}

export function formatRuleResults(matches: RuleMatch[], format: 'text' | 'json' = 'text'): string {
  if (format === 'json') {
    return JSON.stringify({ matches, total: matches.length }, null, 2);
  }

  if (matches.length === 0) {
    return '\nNo rule violations found.\n';
  }

  const bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const m of matches) {
    bySev[m.severity as keyof typeof bySev]++;
  }

  const lines: string[] = [];
  lines.push('\n=== Rule Engine Results ===\n');
  lines.push(`Total: ${matches.length} issues (Critical: ${bySev.critical}, High: ${bySev.high}, Medium: ${bySev.medium}, Low: ${bySev.low})\n`);
  lines.push('─'.repeat(60));

  for (const m of matches) {
    lines.push('\n' + formatRuleMatch(m));
  }

  return lines.join('\n');
}