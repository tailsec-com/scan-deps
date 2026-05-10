export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  ruleId: string;
  type: string;
  severity: Severity;
  title: string;
  file: string;
  line?: number;
  column?: number;
  code?: string;
  matchedText?: string;
  cwe?: string;
  owasp?: string[];
  remediation?: string[];
  tool?: string;
}

export interface ScanResults {
  tool: string;
  version: string;
  results: Finding[];
  stats: {
    filesScanned: number;
    totalFindings: number;
    bySeverity: Record<Severity, number>;
    byType: Record<string, number>;
    duration: number;
  };
}

export function toSARIF(results: ScanResults): object {
  const tool = {
    driver: {
      name: results.tool,
      version: results.version,
      informationUri: 'https://tailsec.io',
      rules: [...new Map(results.results.map(f => [f.ruleId, {
        id: f.ruleId,
        name: f.type,
        shortDescription: { text: f.title },
        properties: {
          'security-severity': severityToSarifSeverity(f.severity),
          'tags': [f.type, f.severity],
        },
      }])).values()],
    },
  };

  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.json',
    runs: [{
      tool,
      results: results.results.map(f => ({
        ruleId: f.ruleId,
        level: severityToLevel(f.severity),
        message: {
          text: f.title,
          arguments: f.file ? [f.file] : [],
        },
        locations: [{
          physicalLocation: {
            artifactLocation: {
              uri: f.file || 'unknown',
              uriBaseId: 'ROOTPATH',
            },
            region: f.line ? {
              startLine: f.line,
              startColumn: f.column || 1,
            } : undefined,
          },
        }],
        properties: {
          cwe: f.cwe,
          owasp: f.owasp,
          matchedText: f.matchedText,
          remediation: f.remediation,
        },
      })),
      properties: {
        metrics: {
          filesScanned: { value: results.stats.filesScanned },
          totalFindings: { value: results.stats.totalFindings },
          critical: { value: results.stats.bySeverity.critical },
          high: { value: results.stats.bySeverity.high },
          medium: { value: results.stats.bySeverity.medium },
          low: { value: results.stats.bySeverity.low },
        },
      },
    }],
  };
}

function severityToSarifSeverity(s: Severity): string {
  switch (s) {
    case 'critical': return '0.9';
    case 'high': return '0.7';
    case 'medium': return '0.5';
    case 'low': return '0.3';
    default: return '0.1';
  }
}

function severityToLevel(s: Severity): string {
  switch (s) {
    case 'critical':
    case 'high': return 'error';
    case 'medium': return 'warning';
    default: return 'note';
  }
}

export function buildScanResults(
  tool: string,
  version: string,
  findings: Finding[],
  filesScanned: number,
  duration: number,
): ScanResults {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  const byType: Record<string, number> = {};

  for (const f of findings) {
    bySeverity[f.severity]++;
    byType[f.type] = (byType[f.type] || 0) + 1;
  }

  return {
    tool,
    version,
    results: findings,
    stats: {
      filesScanned,
      totalFindings: findings.length,
      bySeverity,
      byType,
      duration,
    },
  };
}

export function mergeScanResults(base: ScanResults, incoming: ScanResults): ScanResults {
  const mergedFindings = [...base.results, ...incoming.results];
  return buildScanResults(
    'tailsec',
    '0.1.0',
    mergedFindings,
    base.stats.filesScanned + incoming.stats.filesScanned,
    base.stats.duration + incoming.stats.duration,
  );
}