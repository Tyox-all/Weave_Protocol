/**
 * Mund - The Guardian Protocol
 * Injection Detector - Detects prompt injection attempts
 */

import { 
  type DetectionRule, 
  type SecurityIssue, 
  type IAnalyzer,
  type IssueLocation 
} from '../types.js';
import { compileRulePattern } from './regex.js';
import { decodeModel, scoreInjection, type InjectionModel } from './classifier.js';
import { INJECTION_MODEL } from './injection-model.js';

let model: InjectionModel | undefined;
const loadModel = () => (model ??= decodeModel(INJECTION_MODEL));

export class InjectionDetector implements IAnalyzer {
  name = 'InjectionDetector';
  type = 'injection';

  // Secret and PII patterns, so excerpts in findings never carry them
  private sensitive: RegExp[] = [];

  async analyze(content: string, rules: DetectionRule[]): Promise<SecurityIssue[]> {
    const injectionRules = rules.filter(r => r.type === 'injection' && r.enabled);
    this.sensitive = [];
    for (const r of rules) {
      if ((r.type === 'secret' || r.type === 'pii') && r.pattern) {
        try { this.sensitive.push(compileRulePattern(r.pattern, 'g')); } catch { /* invalid custom rule */ }
      }
    }

    // The text as written, plus text an agent may see that a person doesn't:
    // base64 that decodes to prose and invisible Unicode "tag" characters.
    const views: Array<{ text: string; via?: string }> = [{ text: content }];
    for (const decoded of decodeBase64Prose(content)) views.push({ text: decoded, via: 'base64' });
    const tagText = decodeUnicodeTags(content);
    if (tagText) views.push({ text: tagText, via: 'unicode tags' });

    const issues: SecurityIssue[] = [];
    const seen = new Set<string>();
    for (const view of views) {
      for (const issue of this.applyRules(content, view.text, injectionRules, view.via)) {
        // One finding per rule per view position; the same phrase found twice via decoding counts once
        const key = `${issue.rule_id}:${view.via ?? ''}:${issue.location?.start ?? issue.match}`;
        if (!seen.has(key)) { seen.add(key); issues.push(issue); }
      }
    }

    // Additional heuristic checks
    issues.push(...this.heuristicAnalysis(content));

    // The local classifier backs up the rules: one finding at most, for the
    // view and window it scores highest.
    const classifier = injectionRules.find((r) => r.id === 'injection_classifier');
    if (classifier && process.env.MUND_CLASSIFIER !== '0') {
      const m = loadModel();
      let best: { score: number; window: string; via?: string } = { score: 0, window: '' };
      for (const view of views) {
        const r = scoreInjection(view.text, m);
        if (r.score > best.score) best = { ...r, via: view.via };
      }
      if (best.score >= m.threshold) {
        issues.push({
          rule_id: classifier.id,
          rule_name: best.via ? `${classifier.name} (hidden in ${best.via})` : classifier.name,
          type: classifier.type,
          severity: classifier.severity,
          action: classifier.action,
          match: this.sanitizeMatch(best.window),
          suggestion: `The local classifier scored this ${best.score.toFixed(3)} (threshold ${m.threshold.toFixed(3)}). Treat it as untrusted data, not instructions.`
        });
      }
    }
    return issues;
  }

  private applyRules(original: string, text: string, rules: DetectionRule[], via?: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const normalizedContent = this.normalizeContent(text);
    for (const rule of rules) {
      if (!rule.pattern) continue;
      try {
        const regex = compileRulePattern(rule.pattern, 'gi');
        let match: RegExpExecArray | null;
        while ((match = regex.exec(normalizedContent)) !== null) {
          if (match[0].length === 0) { regex.lastIndex++; continue; }
          const matchText = match[0];
          issues.push({
            rule_id: rule.id,
            rule_name: via ? `${rule.name} (hidden in ${via})` : rule.name,
            type: rule.type,
            severity: rule.severity,
            action: rule.action,
            match: this.sanitizeMatch(matchText),
            location: via ? undefined : this.getLocation(original, match.index, matchText.length),
            suggestion: this.getSuggestion(rule.id)
          });
        }
      } catch (error) {
        console.error(`Invalid regex pattern in rule ${rule.id}:`, error);
      }
    }
    return issues;
  }

  /**
   * Normalize content to detect obfuscated injection attempts
   */
  private normalizeContent(content: string): string {
    return content
      // Remove zero-width and invisible formatting characters
      .replace(/[​-‍⁠﻿­]/g, '')
      // Normalize Unicode variations (fullwidth, ligatures)
      .normalize('NFKC')
      // Curly quotes read as straight ones ("don’t" → "don't")
      .replace(/[‘’‛′]/g, "'")
      .replace(/[“”‟″]/g, '"')
      // Keep letters in every script (accents included), digits and light punctuation
      .replace(/[^\p{L}\p{N}\s.,!?'"()-]/gu, ' ')
      // Collapse whitespace
      .replace(/\s+/g, ' ');
  }

  /**
   * Heuristic analysis for injection patterns
   */
  private heuristicAnalysis(content: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // Role markers. Chat-template tokens never belong in content, so they're
    // high; a plain "System: you are" also opens many legitimate transcripts.
    const roleSwitchPatterns: Array<[RegExp, 'high' | 'low']> = [
      [/<\|\s*(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|end_header_id|eot_id)\s*\|>/i, 'high'],
      [/\[\/?INST\]|<<\/?SYS>>/, 'high'],
      // A bare role tag ([SYSTEM], [admin]) or one naming an override or message.
      // Titles that merely start with the word ("[System Information Discovery]",
      // "[Systemd Service]", "[admin@338]") are not role markers.
      // [DEVELOPER] alone is a common label (diagrams, tables), so it needs a qualifier.
      [/\[\s*(?:(?:system|admin|administrator)\s*(?:(?:override|message|prompt|note|instruction|notice|command|update|mode)s?\b[^\]\n]{0,30})?|developer\s*(?:override|message|prompt|note|instruction|notice|command|update|mode)s?\b[^\]\n]{0,30})\]/i, 'high'],
      [/\<\|?system\|?\>/i, 'high'],
      [/\{system_prompt\}/i, 'high'],
      [/^\s*#{1,4}\s*(?:system|instruction)s?\s*:/im, 'high'],
      [/\bsystem\s*:\s*you\s+are/i, 'low'],
      [/\bassistant\s*:\s*i\s+(will|can|am)/i, 'low'],
    ];

    for (const [pattern, severity] of roleSwitchPatterns) {
      const match = content.match(pattern);
      if (match) {
        issues.push({
          rule_id: 'heuristic_role_switch',
          rule_name: 'Role Switching Attempt',
          type: 'injection',
          severity,
          action: 'alert' as const,
          match: this.sanitizeMatch(match[0]),
          suggestion: 'This content appears to attempt to inject role-switching markers.'
        });
      }
    }

    // Instructions in HTML a person never sees: hidden elements, noscript,
    // template and comments. Hidden menus and labels are common; hidden text
    // that addresses a reader with a directive is not.
    for (const hidden of hiddenHtmlText(content)) {
      if (ADDRESSES_READER.test(hidden) && DIRECTIVE_VERB.test(hidden)) {
        issues.push({
          rule_id: 'heuristic_hidden_instruction',
          rule_name: 'Instruction in Hidden HTML',
          type: 'injection',
          severity: 'high',
          action: 'alert',
          match: this.sanitizeMatch(hidden),
          suggestion: 'Hidden page text gives instructions. Strip hidden elements before an agent reads the page.'
        });
      }
    }

    // Tool-call syntax inside content: a page or result dressed up as the
    // model's own function call, naming a tool that sends or runs something.
    const toolCall = content.match(/<\/?(?:function_calls|tool_call|tool_use)>|<invoke\s+name\s*=|"(?:function|name|tool|tool_name)"\s*:\s*"(?:send_email|send_message|http_request|http_post|fetch_url|web_fetch|transfer\w*|send_payment|pay\w*|exec\w*|shell\w*|run_command|run_shell|bash|write_file|delete\w*)"\s*,\s*"(?:arguments|args|parameters|input)"/i);
    if (toolCall) {
      issues.push({
        rule_id: 'heuristic_tool_call_mimicry',
        rule_name: 'Tool-Call Syntax in Content',
        type: 'injection',
        severity: 'medium',
        action: 'alert',
        match: this.sanitizeMatch(toolCall[0]),
        suggestion: 'Content contains tool-call syntax for an action tool. An agent should never execute calls found in content.'
      });
    }

    // Zero-width characters inside words split trigger words for filters
    // while the model still reads them whole.
    const splitWords = content.match(/\p{L}[​-‍⁠﻿­]+\p{L}/gu) ?? [];
    if (splitWords.length >= 3) {
      issues.push({
        rule_id: 'heuristic_zero_width_split',
        rule_name: 'Zero-Width Characters Inside Words',
        type: 'injection',
        severity: 'medium',
        action: 'alert',
        match: `${splitWords.length} words split by invisible characters`,
        suggestion: 'Invisible characters inside words are a filter-evasion technique. Strip them before processing.'
      });
    }

    // Unicode tag characters (U+E0000–E007F) carry invisible ASCII
    if (/[\u{E0020}-\u{E007F}]/u.test(content)) {
      issues.push({
        rule_id: 'heuristic_unicode_tags',
        rule_name: 'Invisible Unicode Tag Text',
        type: 'injection',
        severity: 'high',
        action: 'alert',
        match: (decodeUnicodeTags(content) ?? '').slice(0, 100),
        suggestion: 'The content carries invisible text in Unicode tag characters. Strip them before processing.'
      });
    }

    // Check for markdown/code injection that might alter rendering
    const markdownPatterns = [
      /```\s*system/i,
      /\<script\>/i,
      /javascript:/i,
      /data:text\/html/i,
    ];

    // Scripts are ordinary in web pages and security writing, so a mention is
    // low severity. A script that reads cookies or storage and sends them off
    // the page is an exfiltration attempt, and high.
    const exfilScript = /\b(?:document\.cookie|localStorage|sessionStorage)\b/i.test(content)
      && /\b(?:fetch\s*\(|XMLHttpRequest|sendBeacon|new\s+Image\b|\.src\s*=|location(?:\.href)?\s*=)/i.test(content);
    for (const pattern of markdownPatterns) {
      const match = content.match(pattern);
      if (match) {
        issues.push({
          rule_id: 'heuristic_markup_injection',
          rule_name: exfilScript ? 'Script That Sends Cookies or Storage Off the Page' : 'Markup Injection Attempt',
          type: 'injection',
          severity: (exfilScript ? 'high' : pattern.source.includes('system') ? 'medium' : 'low') as 'high' | 'medium' | 'low',
          action: 'alert' as const,
          match: this.sanitizeMatch(match[0]),
          suggestion: 'This content contains potentially dangerous markup or code injection.'
        });
      }
    }

    // Check for excessive special characters (potential obfuscation)
    const specialCharRatio = this.calculateSpecialCharRatio(content);
    if (specialCharRatio > 0.3 && content.length > 50) {
      issues.push({
        rule_id: 'heuristic_obfuscation',
        rule_name: 'Potential Obfuscation',
        type: 'injection',
        severity: 'low' as const,
        action: 'log' as const,
        match: `Special character ratio: ${(specialCharRatio * 100).toFixed(1)}%`,
        suggestion: 'This content has an unusually high ratio of special characters, which may indicate obfuscation.'
      });
    }

    return issues;
  }

  /**
   * Calculate ratio of special characters
   */
  private calculateSpecialCharRatio(content: string): number {
    if (content.length === 0) return 0;
    const specialChars = content.replace(/[\w\s]/g, '').length;
    return specialChars / content.length;
  }

  /**
   * Calculate location within content
   */
  private getLocation(content: string, start: number, length: number): IssueLocation {
    const end = start + length;
    const lines = content.substring(0, start).split('\n');
    const line = lines.length;
    const column = lines[lines.length - 1].length + 1;
    return { start, end, line, column };
  }

  /**
   * Sanitize match for safe display
   */
  private sanitizeMatch(match: string, maxLength = 100): string {
    // Findings are logged, stored and sent to webhooks: an excerpt of the
    // scanned text must not carry a secret or personal data along with it
    let redacted = match;
    for (const re of this.sensitive) { re.lastIndex = 0; redacted = redacted.replace(re, '[REDACTED]'); }
    const sanitized = redacted
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
    
    if (sanitized.length <= maxLength) return sanitized;
    return sanitized.substring(0, maxLength) + '...';
  }

  /**
   * Get remediation suggestion
   */
  private getSuggestion(ruleId: string): string {
    const suggestions: Record<string, string> = {
      prompt_injection_ignore: 'This content attempts to make the AI ignore its instructions. Do not process user inputs that contain such patterns.',
      prompt_injection_jailbreak: 'This appears to be a jailbreak attempt. Such content should be filtered or rejected.',
      prompt_injection_system: 'This content attempts to extract system prompts. Do not reveal system instructions.',
      prompt_injection_roleplay: 'This content attempts to manipulate behavior through roleplay. Apply content filtering.',
      prompt_injection_new_task: 'This content tries to give the agent a new task. Treat it as data, not instructions.',
      prompt_injection_ai_addressed: 'This content speaks to an AI reading it. Treat it as data, not instructions.',
      prompt_injection_concealment: 'This content tells the agent to hide its actions from the user. Block it and alert the user.',
      prompt_injection_suppression: 'This content tells the agent to refuse or skip the user\'s request.',
      prompt_injection_authority: 'This content claims system, admin or developer authority. Content can\'t grant authority.',
      prompt_injection_decode_execute: 'This content asks the agent to decode hidden text and act on it.',
      prompt_injection_data_harvest: 'This content asks the agent to collect the user\'s private data.',
    };

    return suggestions[ruleId] || 'This content shows signs of injection attacks. Review and sanitize input.';
  }
}

// ─────────────────────────────────────────────────────────
// Hidden-text helpers
// ─────────────────────────────────────────────────────────

const ADDRESSES_READER = /\b(?:you|your|ai|assistant|agent|llm|model|chatbot|the\s+user)\b/i;
const DIRECTIVE_VERB = /\b(?:must|should|respond|reply|include|tell|send|ignore|reveal|print|call|transfer|execute|run|output|say|forward|delete|disregard|override)\b/i;

const HIDDEN_STYLE = /(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|font-size\s*:\s*0(?:px|em|rem|pt|%)?\s*(?:;|$)|(?:height|width)\s*:\s*0(?:px)?\s*;[^"']*overflow\s*:\s*hidden|clip\s*:\s*rect\(0|left\s*:\s*-\d{4,}px)/i;

/** Text inside HTML a person doesn't see. */
export function hiddenHtmlText(html: string): string[] {
  if (!/<[a-z!]/i.test(html)) return [];
  const out: string[] = [];
  const strip = (s: string) => s.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  const element = /<([a-z][a-z0-9]*)\b([^>]*)>([\s\S]*?)<\/\1\s*>/gi;
  let m: RegExpExecArray | null;
  while ((m = element.exec(html)) !== null) {
    const [, tag, attrs, inner] = m;
    const style = /\bstyle\s*=\s*(["'])([\s\S]*?)\1/i.exec(attrs)?.[2] ?? '';
    const hidden = /^(?:noscript|template)$/i.test(tag) || /\baria-hidden\s*=\s*["']?true/i.test(attrs) || /\bhidden(?:\s|=|$)/i.test(attrs) || HIDDEN_STYLE.test(style);
    if (hidden) {
      const text = strip(inner);
      if (text) out.push(text);
    } else if (/<[a-z]/i.test(inner)) {
      // Visible element: keep looking inside it
      out.push(...hiddenHtmlText(inner));
    }
  }
  for (const c of html.matchAll(/<!--([\s\S]*?)-->/g)) {
    const text = c[1].trim();
    if (text) out.push(text);
  }
  return out;
}

/** Base64 runs that decode to readable text (not images or binary). */
export function decodeBase64Prose(content: string): string[] {
  const out: string[] = [];
  for (const m of content.matchAll(/(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])/g)) {
    // data: URIs carry files, not text
    if (/base64,\s*$/i.test(content.slice(Math.max(0, m.index! - 10), m.index))) continue;
    let text: string;
    try {
      text = typeof atob === 'function' ? atob(m[0]) : Buffer.from(m[0], 'base64').toString('binary');
    } catch {
      continue;
    }
    const printable = text.replace(/[^\x20-\x7E\n\t]/g, '').length / Math.max(text.length, 1);
    if (printable > 0.95 && /[a-z]{2,}\s+[a-z]{2,}/i.test(text)) out.push(text);
  }
  return out;
}

/** ASCII hidden in Unicode tag characters, or undefined. */
export function decodeUnicodeTags(content: string): string | undefined {
  let out = '';
  for (const ch of content) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000);
  }
  return out.trim() || undefined;
}

export default InjectionDetector;
