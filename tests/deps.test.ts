import { scanDeps, formatDepsOutput } from '../src/deps.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import * as os from 'os';

describe('scanDeps', () => {
  let tempDir: string;

  afterEach(() => {
    if (tempDir) {
      rmSync(tempDir, { recursive: true });
    }
  });

  test('Scan package.json with no bad deps → 0 findings', () => {
    tempDir = join(os.tmpdir(), `tailsec-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-pkg',
      dependencies: { 'axios': '^1.6.0' }
    }, null, 2));

    const findings = scanDeps(join(tempDir, 'package.json'));
    expect(findings).toHaveLength(0);
  });

  test('Scan package.json with event-stream (critical dep) → finds critical-dep-event-stream', () => {
    tempDir = join(os.tmpdir(), `tailsec-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-pkg',
      dependencies: { 'event-stream': '3.3.4' }
    }, null, 2));

    const findings = scanDeps(join(tempDir, 'package.json'));
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('critical-dep-event-stream');
    expect(findings[0].severity).toBe('critical');
  });

  test('Scan package.json with lodash <4.17.21 → finds critical-dep-lodash (checkCriticalDeps matches by name only)', () => {
    tempDir = join(os.tmpdir(), `tailsec-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-pkg',
      dependencies: { 'lodash': '4.17.20' }
    }, null, 2));

    const findings = scanDeps(join(tempDir, 'package.json'));
    expect(findings.some(f => f.ruleId === 'critical-dep-lodash')).toBe(true);
  });

  test('Scan package.json with minimist <1.2.6 → finds critical-dep-minimist', () => {
    tempDir = join(os.tmpdir(), `tailsec-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-pkg',
      dependencies: { 'minimist': '1.2.5' }
    }, null, 2));

    const findings = scanDeps(join(tempDir, 'package.json'));
    expect(findings.some(f => f.ruleId === 'critical-dep-minimist')).toBe(true);
  });

  test('Scan package.json with glob <8.1.0 (known vuln) → finds known-vuln-glob', () => {
    tempDir = join(os.tmpdir(), `tailsec-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-pkg',
      dependencies: { 'glob': '8.0.3' }
    }, null, 2));

    const findings = scanDeps(join(tempDir, 'package.json'));
    expect(findings.some(f => f.ruleId === 'known-vuln-glob')).toBe(true);
    expect(findings[0].severity).toBe('high');
  });

  test('Scan package.json with tar <6.2 (critical dep) → finds critical-dep-tar', () => {
    tempDir = join(os.tmpdir(), `tailsec-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-pkg',
      dependencies: { 'tar': '6.1.1' }
    }, null, 2));

    const findings = scanDeps(join(tempDir, 'package.json'));
    expect(findings.some(f => f.ruleId === 'critical-dep-tar')).toBe(true);
    expect(findings[0].severity).toBe('critical');
  });

  test('Scan package.json with ws <8.17.1 (critical dep) → finds critical-dep-ws', () => {
    tempDir = join(os.tmpdir(), `tailsec-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-pkg',
      dependencies: { 'ws': '8.16.0' }
    }, null, 2));

    const findings = scanDeps(join(tempDir, 'package.json'));
    expect(findings.some(f => f.ruleId === 'critical-dep-ws')).toBe(true);
    expect(findings[0].severity).toBe('critical');
  });

  test('Scan package.json with express <4.19.2 (critical dep) → finds critical-dep-express', () => {
    tempDir = join(os.tmpdir(), `tailsec-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-pkg',
      dependencies: { 'express': '4.19.1' }
    }, null, 2));

    const findings = scanDeps(join(tempDir, 'package.json'));
    expect(findings.some(f => f.ruleId === 'critical-dep-express')).toBe(true);
    expect(findings[0].severity).toBe('critical');
  });

  test('Scan package.json with request (deprecated) → finds critical-dep-request', () => {
    tempDir = join(os.tmpdir(), `tailsec-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-pkg',
      dependencies: { 'request': '2.88.0' }
    }, null, 2));

    const findings = scanDeps(join(tempDir, 'package.json'));
    expect(findings.some(f => f.ruleId === 'critical-dep-request')).toBe(true);
    expect(findings[0].severity).toBe('critical');
  });

  test('Scan package.json with moment (deprecated) → finds critical-dep-moment', () => {
    tempDir = join(os.tmpdir(), `tailsec-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-pkg',
      dependencies: { 'moment': '2.29.4' }
    }, null, 2));

    const findings = scanDeps(join(tempDir, 'package.json'));
    expect(findings.some(f => f.ruleId === 'critical-dep-moment')).toBe(true);
    expect(findings[0].severity).toBe('critical');
  });

  test('Scan package.json with eslint-scope <3.7.2 → finds critical-dep-eslint-scope (any version)', () => {
    tempDir = join(os.tmpdir(), `tailsec-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-pkg',
      dependencies: { 'eslint-scope': '3.7.1' }
    }, null, 2));

    const findings = scanDeps(join(tempDir, 'package.json'));
    expect(findings.some(f => f.ruleId === 'critical-dep-eslint-scope')).toBe(true);
    expect(findings[0].severity).toBe('critical');
  });

  test('Scan package.json with tar <6.1.13 → finds critical-dep-tar (higher severity takes precedence)', () => {
    tempDir = join(os.tmpdir(), `tailsec-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-pkg',
      dependencies: { 'tar': '6.1.10' }
    }, null, 2));

    const findings = scanDeps(join(tempDir, 'package.json'));
    expect(findings.some(f => f.ruleId === 'critical-dep-tar')).toBe(true);
    expect(findings[0].severity).toBe('critical');
  });

  test('Scan package.json with postcss <8.4.31 → finds known-vuln-postcss', () => {
    tempDir = join(os.tmpdir(), `tailsec-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-pkg',
      dependencies: { 'postcss': '8.4.30' }
    }, null, 2));

    const findings = scanDeps(join(tempDir, 'package.json'));
    expect(findings.some(f => f.ruleId === 'known-vuln-postcss')).toBe(true);
    expect(findings[0].severity).toBe('high');
  });

  test('Scan package.json with json5 <1.0.2 → finds known-vuln-json5', () => {
    tempDir = join(os.tmpdir(), `tailsec-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-pkg',
      dependencies: { 'json5': '1.0.1' }
    }, null, 2));

    const findings = scanDeps(join(tempDir, 'package.json'));
    expect(findings.some(f => f.ruleId === 'known-vuln-json5')).toBe(true);
    expect(findings[0].severity).toBe('high');
  });
});

describe('formatDepsOutput', () => {
  test('Format output text → contains "Dependency Findings"', () => {
    const output = formatDepsOutput([], 'text');
    expect(output).toContain('Dependency Findings');
  });

  test('Format output json → valid JSON with dependencies array', () => {
    const output = formatDepsOutput([], 'json');
    const parsed = JSON.parse(output);
    expect(parsed).toHaveProperty('dependencies');
    expect(Array.isArray(parsed.dependencies)).toBe(true);
    expect(parsed).toHaveProperty('total');
  });

  test('Format output text with findings → contains severity and package info', () => {
    const findings = [{
      ruleId: 'test-rule',
      type: 'dependency',
      severity: 'high',
      title: 'Test finding',
      package: 'test-pkg',
      currentVersion: '1.0.0',
      advice: ['Test advice']
    }];
    const output = formatDepsOutput(findings, 'text');
    expect(output).toContain('HIGH');
    expect(output).toContain('test-pkg@1.0.0');
  });
});
