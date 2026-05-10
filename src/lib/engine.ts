import { readFileSync } from 'fs';
import { basename, extname } from 'path';

export interface TaintFlow {
  source: string;
  sink: string;
  path: string[];
  sanitizers: string[];
}

export interface MatchResult {
  ruleId: string;
  type: string;
  severity: string;
  title: string;
  line: number;
  column: number;
  endLine?: number;
  code: string;
  matchedText: string;
}

const LANG_EXTENSIONS: Record<string, string[]> = {
  javascript: ['.js', '.jsx', '.mjs', '.cjs'],
  typescript: ['.ts', '.tsx', '.mts', '.cts'],
  python: ['.py', '.pyw'],
  java: ['.java'],
  csharp: ['.cs'],
  php: ['.php'],
  ruby: ['.rb'],
  go: ['.go'],
  rust: ['.rs'],
  cpp: ['.cpp', '.cc', '.cxx', '.h', '.hpp'],
  c: ['.c', '.h'],
};

const LANGUAGE_PATTERNS: Record<string, RegExp[]> = {
  javascript: [
    /\bdocument\.write\s*\(/,
    /\binnerHTML\s*=/,
    /\beval\s*\(/,
    /\bFunction\s*\(/,
    /\bsetTimeout\s*\(.*,\s*0\)/,
    /`\$\{.*\}\`/,
  ],
  typescript: [
    /\bdocument\.write\s*\(/,
    /\binnerHTML\s*=/
  ],
  python: [
    /\beval\s*\(/,
    /\bexec\s*\(/,
    /\bos\.system\s*\(/,
    /\bsubprocess\.call\s*\(/,
    /\bpickle\.load\s*\(/,
  ],
};

export function detectLanguage(filePath: string): string {
  const ext = extname(filePath).toLowerCase();
  const bn = basename(filePath).toLowerCase();

  if (bn === 'dockerfile') return 'dockerfile';
  if (bn === 'makefile' || bn === 'makefile') return 'makefile';
  if (bn === 'jenkinsfile') return 'groovy';

  for (const [lang, extensions] of Object.entries(LANG_EXTENSIONS)) {
    if (extensions.includes(ext)) return lang;
  }

  return 'unknown';
}

export function getLineStarts(content: string): number[] {
  const starts: number[] = [0];
  for (let i = 0; i < content.length; i++) {
    if (content[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

export function getLineAndColumn(offset: number, lineStarts: number[]): { line: number; column: number } {
  let line = 0;
  while (line < lineStarts.length - 1 && lineStarts[line + 1] <= offset) {
    line++;
  }
  return { line: line + 1, column: offset - lineStarts[line] + 1 };
}

export function getLineContent(content: string, line: number): string {
  const starts = getLineStarts(content);
  if (line < 1 || line > starts.length) return '';
  const start = starts[line - 1];
  const end = starts[line] || content.length;
  return content.slice(start, end).trimEnd();
}

export function findAllMatches(content: string, pattern: RegExp): { line: number; column: number; matched: string; index: number }[] {
  const results: { line: number; column: number; matched: string; index: number }[] = [];
  const lineStarts = getLineStarts(content);

  pattern.lastIndex = 0;
  let match;
  while ((match = pattern.exec(content)) !== null) {
    const pos = match.index;
    const { line, column } = getLineAndColumn(pos, lineStarts);
    results.push({ line, column, matched: match[0], index: pos });
    if (!pattern.global) break;
  }

  return results;
}

export function getContext(content: string, line: number, before = 2, after = 2): string {
  const starts = getLineStarts(content);
  const totalLines = starts.length;

  const startLine = Math.max(1, line - before);
  const endLine = Math.min(totalLines, line + after);

  const context: string[] = [];
  for (let l = startLine; l <= endLine; l++) {
    const lineContent = getLineContent(content, l);
    const prefix = l === line ? '>>> ' : '    ';
    context.push(`${prefix}${l}: ${lineContent}`);
  }

  return context.join('\n');
}

export function isCommentLine(line: string, lang: string): boolean {
  const trimmed = line.trim();
  if (lang === 'python' && (trimmed.startsWith('#') || trimmed.startsWith('"""') || trimmed.startsWith("'''"))) return true;
  if (trimmed.startsWith('//')) return true;
  if (trimmed.startsWith('/*')) return true;
  if (trimmed.startsWith('*')) return true;
  if (trimmed.startsWith('--')) return true;
  if (trimmed.startsWith('<!--')) return true;
  return false;
}

export function isStringLiteral(line: string, col: number): boolean {
  let inString = false;
  let stringChar = '';
  for (let i = 0; i < line.length; i++) {
    if (!inString && (line[i] === '"' || line[i] === "'" || line[i] === '`')) {
      inString = true;
      stringChar = line[i];
    } else if (inString && line[i] === stringChar && line[i - 1] !== '\\') {
      inString = false;
    }
  }
  return inString;
}

export function extractCodeContext(content: string, line: number, pattern: RegExp): string {
  const lineStarts = getLineStarts(content);
  const starts = lineStarts[line - 1];
  const ends = lineStarts[line] || content.length;

  let start = starts;
  while (start > 0 && content[start - 1] !== '\n') start--;

  let end = ends - 1;
  while (end < content.length && content[end] !== '\n') end++;

  const lineContent = content.slice(start, end);
  const trimmed = lineContent.trim();

  const match = pattern.exec(trimmed);
  if (match) {
    const offset = pattern.lastIndex - match[0].length;
    const snippetStart = Math.max(0, offset - 20);
    const snippetEnd = Math.min(trimmed.length, offset + match[0].length + 20);
    return trimmed.slice(snippetStart, snippetEnd);
  }

  return trimmed.slice(0, 100);
}

export const SANITIZERS: Record<string, string[]> = {
  sql: ['escape', 'quote', 'sanitize', 'param', 'query', 'prepare', 'bind'],
  html: ['escape', 'sanitize', 'textContent', 'innerText'],
  shell: ['escape', 'shellquote', 'shellescape'],
  path: ['normalize', 'resolve', 'basename', 'dirname'],
  url: ['encodeURI', 'encodeURIComponent'],
};

export function hasSanitizer(code: string, sink: string, sanitizerList: string[]): boolean {
  const sinkStart = code.indexOf(sink);
  if (sinkStart === -1) return false;

  const afterSink = code.slice(sinkStart + sink.length, sinkStart + sink.length + 100);
  return sanitizerList.some(s => afterSink.includes(s));
}

export function findTaintFlows(content: string, sources: string[], sinks: string[], sanitizerList: string[]): TaintFlow[] {
  const flows: TaintFlow[] = [];

  for (const source of sources) {
    for (const sink of sinks) {
      const sourceIdx = content.indexOf(source);
      const sinkIdx = content.indexOf(sink);

      if (sourceIdx !== -1 && sinkIdx !== -1 && sourceIdx < sinkIdx) {
        const between = content.slice(sourceIdx, sinkIdx + sink.length);
        const hasSanit = hasSanitizer(between, sink, sanitizerList);
        if (!hasSanit) {
          flows.push({
            source,
            sink,
            path: [source, sink],
            sanitizers: [],
          });
        }
      }
    }
  }

  return flows;
}