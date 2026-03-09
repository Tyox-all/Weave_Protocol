/**
 * Mund - The Guardian Protocol
 * MCP Server Analyzer - Scans MCP server manifests for security issues
 * 
 * Detects:
 * - Prompt injection in tool descriptions ("line jumping" attacks)
 * - Hidden Unicode characters
 * - Dangerous permission patterns
 * - Embedded secrets
 * - Typosquatting of legitimate server names
 */

import { 
  type DetectionRule, 
  type SecurityIssue, 
  type IAnalyzer,
  type IssueLocation 
} from '../types.js';

// ============================================================================
// Types
// ============================================================================

export interface McpServerManifest {
  name: string;
  version: string;
  description?: string;
  tools?: McpToolDefinition[];
  resources?: McpResourceDefinition[];
  prompts?: McpPromptDefinition[];
  repository?: string;
  author?: string;
}

export interface McpToolDefinition {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface McpResourceDefinition {
  name: string;
  description?: string;
  uri?: string;
  mimeType?: string;
}

export interface McpPromptDefinition {
  name: string;
  description?: string;
  arguments?: Array<{
    name: string;
    description?: string;
    required?: boolean;
  }>;
}

export interface McpScanResult {
  server_name: string;
  version: string;
  scanned_at: string;
  source?: string;
  issue_count: number;
  by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  recommendation: 'DO_NOT_INSTALL' | 'REVIEW_CAREFULLY' | 'CAUTION' | 'APPEARS_SAFE';
  capabilities: McpCapabilities;
  issues: SecurityIssue[];
}

export interface McpCapabilities {
  network: boolean;
  filesystem: boolean;
  execution: boolean;
  environment: boolean;
  database: boolean;
  crypto: boolean;
}

// ============================================================================
// Constants
// ============================================================================

/** Known legitimate MCP server names for typosquatting detection */
const LEGITIMATE_SERVERS = [
  // Official/common servers
  'filesystem', 'github', 'gitlab', 'slack', 'notion', 'linear',
  'postgres', 'postgresql', 'sqlite', 'mysql', 'redis', 'mongodb',
  'elasticsearch', 'google-drive', 'dropbox', 'aws', 'azure', 'gcp',
  'docker', 'kubernetes', 'terraform', 'ansible', 'jenkins',
  'jira', 'confluence', 'asana', 'trello', 'monday',
  'stripe', 'twilio', 'sendgrid', 'mailchimp',
  'openai', 'anthropic', 'huggingface', 'replicate',
  'vercel', 'netlify', 'heroku', 'railway',
  'supabase', 'firebase', 'planetscale', 'neon',
  'brave-search', 'puppeteer', 'playwright', 'selenium',
  'fetch', 'memory', 'time', 'sequential-thinking',
  // Weave Protocol
  'mund', 'hord', 'domere', 'witan'
];

/** Injection patterns commonly found in "line jumping" attacks */
const INJECTION_PATTERNS = [
  // Direct instruction override
  { pattern: /ignore\s+(previous|all|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)/i, name: 'Instruction Override' },
  { pattern: /disregard\s+(your|the|all|any)\s+(rules?|guidelines?|instructions?|constraints?)/i, name: 'Rule Disregard' },
  { pattern: /forget\s+(everything|all|your)\s+(previous|prior|above)?/i, name: 'Memory Wipe' },
  
  // Role manipulation
  { pattern: /you\s+are\s+now\s+(a|an|the)?\s*[a-z]+/i, name: 'Role Reassignment' },
  { pattern: /act\s+as\s+(if\s+you\s+are\s+)?(a|an|the)?\s*[a-z]+/i, name: 'Role Acting' },
  { pattern: /pretend\s+(to\s+be|you\s+are)/i, name: 'Role Pretend' },
  { pattern: /from\s+now\s+on,?\s+you/i, name: 'Behavior Override' },
  
  // System prompt extraction
  { pattern: /reveal\s+(your|the)\s+(system|initial)\s*(prompt|instructions?)/i, name: 'Prompt Extraction' },
  { pattern: /what\s+(is|are)\s+your\s+(system|initial|original)\s*(prompt|instructions?)/i, name: 'Prompt Query' },
  { pattern: /show\s+me\s+(your|the)\s+(system|hidden)/i, name: 'System Reveal' },
  
  // Markup injection
  { pattern: /\[SYSTEM\]/i, name: 'System Tag Injection' },
  { pattern: /<\|?(system|assistant|user)\|?>/i, name: 'Role Tag Injection' },
  { pattern: /```\s*(system|python.*exec|bash|sh)\s/i, name: 'Code Block Injection' },
  { pattern: /\{\{system/i, name: 'Template Injection' },
  
  // Jailbreak patterns
  { pattern: /DAN\s*mode/i, name: 'DAN Jailbreak' },
  { pattern: /developer\s+mode\s+(enabled|on|active)/i, name: 'Developer Mode Jailbreak' },
  { pattern: /bypass\s+(your|the|all)?\s*(safety|security|filter|restriction)/i, name: 'Safety Bypass' },
  { pattern: /override\s+(safety|security|content)\s*(filter|policy|check)/i, name: 'Filter Override' },
  
  // Hypothetical framing (common evasion)
  { pattern: /hypothetically,?\s+(if|what\s+if)\s+you\s+(could|were|had)/i, name: 'Hypothetical Evasion' },
  { pattern: /in\s+a\s+fictional\s+(world|scenario|story)/i, name: 'Fiction Framing' },
];

/** Patterns indicating dangerous capabilities */
const DANGEROUS_CAPABILITY_PATTERNS = [
  // Command execution
  { pattern: /\b(exec|execute|shell|command|bash|sh|cmd|spawn|fork)\b/i, capability: 'execution', risk: 'Command execution' },
  { pattern: /\b(child_process|subprocess|system\(|popen)\b/i, capability: 'execution', risk: 'Process spawning' },
  
  // Network access
  { pattern: /\b(fetch|request|http|https|curl|wget|axios|got)\b/i, capability: 'network', risk: 'Network requests' },
  { pattern: /\b(socket|websocket|tcp|udp|net\.connect)\b/i, capability: 'network', risk: 'Raw socket access' },
  { pattern: /\b(dns|resolve|lookup)\b/i, capability: 'network', risk: 'DNS operations' },
  
  // Filesystem
  { pattern: /\b(file|read|write|unlink|rmdir|mkdir|chmod|chown)\b/i, capability: 'filesystem', risk: 'Filesystem access' },
  { pattern: /\b(path|directory|folder|fs\.|fopen|fwrite)\b/i, capability: 'filesystem', risk: 'Path operations' },
  
  // Code evaluation
  { pattern: /\b(eval|Function\(|vm\.run|new\s+Function)\b/i, capability: 'execution', risk: 'Code evaluation' },
  { pattern: /\b(require|import|__import__|importlib)\b/i, capability: 'execution', risk: 'Dynamic imports' },
  
  // Environment/secrets
  { pattern: /\b(env|environment|process\.env|os\.environ|getenv)\b/i, capability: 'environment', risk: 'Environment access' },
  { pattern: /\b(secret|credential|password|token|apikey|api_key)\b/i, capability: 'environment', risk: 'Credential access' },
  
  // Database
  { pattern: /\b(sql|query|database|db|postgres|mysql|mongo|redis)\b/i, capability: 'database', risk: 'Database operations' },
  { pattern: /\b(select|insert|update|delete|drop|truncate)\b/i, capability: 'database', risk: 'SQL operations' },
  
  // Crypto (not inherently bad, but noteworthy)
  { pattern: /\b(crypto|encrypt|decrypt|hash|sign|verify|cipher)\b/i, capability: 'crypto', risk: 'Cryptographic operations' },
];

/** Secret patterns to detect in manifests */
const SECRET_PATTERNS = [
  { pattern: /sk-[a-zA-Z0-9]{20,}/, name: 'OpenAI API Key' },
  { pattern: /sk-ant-[a-zA-Z0-9-]{90,}/, name: 'Anthropic API Key' },
  { pattern: /ghp_[a-zA-Z0-9]{36}/, name: 'GitHub Personal Access Token' },
  { pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/, name: 'GitHub Fine-Grained Token' },
  { pattern: /gho_[a-zA-Z0-9]{36}/, name: 'GitHub OAuth Token' },
  { pattern: /xox[baprs]-[a-zA-Z0-9-]{10,}/, name: 'Slack Token' },
  { pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9/]+/, name: 'Slack Webhook' },
  { pattern: /sk_live_[a-zA-Z0-9]{24,}/, name: 'Stripe Live Key' },
  { pattern: /sk_test_[a-zA-Z0-9]{24,}/, name: 'Stripe Test Key' },
  { pattern: /AKIA[0-9A-Z]{16}/, name: 'AWS Access Key ID' },
  { pattern: /[a-zA-Z0-9/+=]{40}/, name: 'Potential AWS Secret Key', entropyCheck: true },
  { pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/, name: 'JWT Token' },
  { pattern: /-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----/, name: 'Private Key' },
  { pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/, name: 'MongoDB Connection String' },
  { pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@/, name: 'PostgreSQL Connection String' },
  { pattern: /mysql:\/\/[^:]+:[^@]+@/, name: 'MySQL Connection String' },
  { pattern: /redis:\/\/[^:]+:[^@]+@/, name: 'Redis Connection String' },
];

// ============================================================================
// Analyzer Implementation
// ============================================================================

export class McpServerAnalyzer implements IAnalyzer {
  name = 'McpServerAnalyzer';
  type = 'mcp_server';

  async analyze(content: string, _rules: DetectionRule[]): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];
    
    // Attempt to parse as JSON
    let manifest: McpServerManifest;
    try {
      manifest = JSON.parse(content);
    } catch {
      // Not valid JSON - might be a file path or URL, skip analysis
      return [];
    }

    // Validate it looks like an MCP manifest
    if (!manifest.name && !manifest.tools && !manifest.resources) {
      return []; // Doesn't appear to be an MCP manifest
    }

    // Run all security checks
    issues.push(...this.scanToolDescriptions(manifest));
    issues.push(...this.scanResourceDescriptions(manifest));
    issues.push(...this.scanPromptDescriptions(manifest));
    issues.push(...this.auditPermissions(manifest));
    issues.push(...this.scanForSecrets(content));
    issues.push(...this.checkTyposquatting(manifest));
    issues.push(...this.checkMetadata(manifest));

    return issues;
  }

  /**
   * Scan tool descriptions for injection attacks
   */
  private scanToolDescriptions(manifest: McpServerManifest): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    
    for (const tool of manifest.tools || []) {
      const desc = tool.description || '';
      const name = tool.name || '';
      const combined = `${name} ${desc}`;

      // Check for injection patterns
      for (const { pattern, name: patternName } of INJECTION_PATTERNS) {
        const match = combined.match(pattern);
        if (match) {
          issues.push({
            rule_id: 'mcp_tool_injection',
            rule_name: `Injection Pattern: ${patternName}`,
            type: 'mcp_server',
            severity: 'critical',
            action: 'block',
            match: `Tool "${tool.name}": "${this.truncate(match[0], 50)}"`,
            location: this.createLocation(desc, match.index || 0, match[0].length),
            suggestion: `Tool description contains "${patternName}" injection pattern. DO NOT install this server.`
          });
        }
      }

      // Check for hidden Unicode
      const hiddenUnicode = this.findHiddenUnicode(desc);
      if (hiddenUnicode.length > 0) {
        issues.push({
          rule_id: 'mcp_hidden_unicode',
          rule_name: 'Hidden Unicode Characters',
          type: 'mcp_server',
          severity: 'high',
          action: 'alert',
          match: `Tool "${tool.name}" contains ${hiddenUnicode.length} hidden character(s): ${hiddenUnicode.map(c => `U+${c.charCodeAt(0).toString(16).toUpperCase()}`).join(', ')}`,
          suggestion: 'Hidden Unicode characters may conceal malicious instructions. Inspect the raw content carefully.'
        });
      }

      // Check for suspicious length (very long descriptions may hide content)
      if (desc.length > 2000) {
        issues.push({
          rule_id: 'mcp_suspicious_length',
          rule_name: 'Suspiciously Long Description',
          type: 'mcp_server',
          severity: 'medium',
          action: 'alert',
          match: `Tool "${tool.name}" has ${desc.length} character description`,
          suggestion: 'Unusually long tool descriptions may hide malicious content. Review the full description carefully.'
        });
      }

      // Check inputSchema for suspicious defaults
      if (tool.inputSchema) {
        const schemaIssues = this.scanInputSchema(tool.name, tool.inputSchema);
        issues.push(...schemaIssues);
      }
    }

    return issues;
  }

  /**
   * Scan resource descriptions
   */
  private scanResourceDescriptions(manifest: McpServerManifest): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    
    for (const resource of manifest.resources || []) {
      const desc = resource.description || '';
      
      // Check for injection patterns
      for (const { pattern, name: patternName } of INJECTION_PATTERNS) {
        if (pattern.test(desc)) {
          issues.push({
            rule_id: 'mcp_resource_injection',
            rule_name: `Injection in Resource: ${patternName}`,
            type: 'mcp_server',
            severity: 'critical',
            action: 'block',
            match: `Resource "${resource.name}"`,
            suggestion: `Resource description contains injection pattern. DO NOT install this server.`
          });
        }
      }

      // Check resource URI for suspicious patterns
      if (resource.uri) {
        if (/^(file|data|javascript):/i.test(resource.uri)) {
          issues.push({
            rule_id: 'mcp_suspicious_uri',
            rule_name: 'Suspicious Resource URI',
            type: 'mcp_server',
            severity: 'high',
            action: 'alert',
            match: `Resource "${resource.name}" uses ${resource.uri.split(':')[0]}: URI scheme`,
            suggestion: 'This URI scheme may allow access to local files or execute code.'
          });
        }
      }
    }

    return issues;
  }

  /**
   * Scan prompt template descriptions
   */
  private scanPromptDescriptions(manifest: McpServerManifest): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    
    for (const prompt of manifest.prompts || []) {
      const desc = prompt.description || '';
      
      for (const { pattern, name: patternName } of INJECTION_PATTERNS) {
        if (pattern.test(desc)) {
          issues.push({
            rule_id: 'mcp_prompt_injection',
            rule_name: `Injection in Prompt: ${patternName}`,
            type: 'mcp_server',
            severity: 'critical',
            action: 'block',
            match: `Prompt "${prompt.name}"`,
            suggestion: `Prompt description contains injection pattern. DO NOT install this server.`
          });
        }
      }
    }

    return issues;
  }

  /**
   * Scan input schema for suspicious default values
   */
  private scanInputSchema(toolName: string, schema: Record<string, unknown>): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const schemaStr = JSON.stringify(schema);

    // Check for injection in schema defaults
    for (const { pattern, name: patternName } of INJECTION_PATTERNS) {
      if (pattern.test(schemaStr)) {
        issues.push({
          rule_id: 'mcp_schema_injection',
          rule_name: `Injection in Schema: ${patternName}`,
          type: 'mcp_server',
          severity: 'critical',
          action: 'block',
          match: `Tool "${toolName}" input schema`,
          suggestion: 'Input schema contains injection patterns in defaults or descriptions.'
        });
      }
    }

    return issues;
  }

  /**
   * Audit tool permissions and capabilities
   */
  auditPermissions(manifest: McpServerManifest): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const capabilities: McpCapabilities = {
      network: false,
      filesystem: false,
      execution: false,
      environment: false,
      database: false,
      crypto: false
    };

    for (const tool of manifest.tools || []) {
      const combined = `${tool.name} ${tool.description || ''}`.toLowerCase();
      
      for (const { pattern, capability, risk } of DANGEROUS_CAPABILITY_PATTERNS) {
        if (pattern.test(combined)) {
          capabilities[capability as keyof McpCapabilities] = true;
          
          // Only flag execution as high severity
          const severity = capability === 'execution' ? 'high' : 'medium';
          
          issues.push({
            rule_id: `mcp_capability_${capability}`,
            rule_name: `Capability: ${risk}`,
            type: 'mcp_server',
            severity: severity as 'high' | 'medium',
            action: 'alert',
            match: `Tool "${tool.name}" may have ${risk.toLowerCase()}`,
            suggestion: `Verify this capability is necessary and from a trusted source.`
          });
        }
      }
    }

    // Flag servers with execution capability
    if (capabilities.execution) {
      issues.push({
        rule_id: 'mcp_execution_warning',
        rule_name: 'Command Execution Capability',
        type: 'mcp_server',
        severity: 'high',
        action: 'alert',
        match: `Server "${manifest.name}" can execute commands`,
        suggestion: 'This server can execute arbitrary commands on your system. Only install from highly trusted sources.'
      });
    }

    // Check for excessive tool count
    const toolCount = manifest.tools?.length || 0;
    if (toolCount > 25) {
      issues.push({
        rule_id: 'mcp_excessive_tools',
        rule_name: 'Excessive Tool Count',
        type: 'mcp_server',
        severity: 'medium',
        action: 'alert',
        match: `${toolCount} tools defined`,
        suggestion: 'Servers with many tools have larger attack surfaces. Consider if all tools are necessary.'
      });
    }

    return issues;
  }

  /**
   * Scan manifest content for embedded secrets
   */
  private scanForSecrets(content: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    for (const { pattern, name, entropyCheck } of SECRET_PATTERNS) {
      const regex = new RegExp(pattern, 'g');
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        // Skip if entropy check is required and entropy is low
        if (entropyCheck && this.calculateEntropy(match[0]) < 4.0) {
          continue;
        }

        issues.push({
          rule_id: 'mcp_embedded_secret',
          rule_name: `Embedded Secret: ${name}`,
          type: 'mcp_server',
          severity: 'critical',
          action: 'block',
          match: this.redactSecret(match[0]),
          location: this.createLocation(content, match.index, match[0].length),
          suggestion: `Server manifest contains hardcoded ${name}. This is a critical security risk. DO NOT install.`
        });
      }
    }

    return issues;
  }

  /**
   * Check for typosquatting of known legitimate servers
   */
  checkTyposquatting(manifest: McpServerManifest): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const name = (manifest.name || '').toLowerCase().replace(/[^a-z0-9]/g, '');

    if (!name) return issues;

    for (const legitimate of LEGITIMATE_SERVERS) {
      const legitNormalized = legitimate.replace(/[^a-z0-9]/g, '');
      
      // Skip exact matches
      if (name === legitNormalized) continue;

      const distance = this.levenshteinDistance(name, legitNormalized);
      
      // Flag if very similar (1-2 edits) or if it's a substring with additions
      if (distance > 0 && distance <= 2) {
        issues.push({
          rule_id: 'mcp_typosquatting',
          rule_name: 'Potential Typosquatting',
          type: 'mcp_server',
          severity: 'high',
          action: 'alert',
          match: `"${manifest.name}" is ${distance} edit(s) away from "${legitimate}"`,
          suggestion: `This server name is suspiciously similar to the legitimate "${legitimate}" server. Verify you have the correct server from a trusted source.`
        });
      }

      // Check for common typosquatting patterns
      if (this.hasTyposquatPattern(name, legitNormalized)) {
        issues.push({
          rule_id: 'mcp_typosquatting_pattern',
          rule_name: 'Typosquatting Pattern Detected',
          type: 'mcp_server',
          severity: 'high',
          action: 'alert',
          match: `"${manifest.name}" uses common typosquatting pattern of "${legitimate}"`,
          suggestion: 'This name uses a known typosquatting technique. Verify the source carefully.'
        });
      }
    }

    return issues;
  }

  /**
   * Check metadata for suspicious patterns
   */
  private checkMetadata(manifest: McpServerManifest): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // Check for missing metadata
    if (!manifest.version) {
      issues.push({
        rule_id: 'mcp_missing_version',
        rule_name: 'Missing Version',
        type: 'mcp_server',
        severity: 'low',
        action: 'log',
        match: 'No version specified',
        suggestion: 'Legitimate servers typically include version information.'
      });
    }

    // Check for suspicious repository URLs
    if (manifest.repository) {
      // Check for URL shorteners or suspicious domains
      const suspiciousDomains = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'shorturl'];
      for (const domain of suspiciousDomains) {
        if (manifest.repository.includes(domain)) {
          issues.push({
            rule_id: 'mcp_suspicious_repo',
            rule_name: 'Suspicious Repository URL',
            type: 'mcp_server',
            severity: 'high',
            action: 'alert',
            match: `Repository uses URL shortener: ${domain}`,
            suggestion: 'Legitimate servers link directly to their repository. URL shorteners can hide malicious destinations.'
          });
        }
      }
    }

    return issues;
  }

  // ============================================================================
  // Helper Methods
  // ============================================================================

  /**
   * Find hidden Unicode characters in a string
   */
  private findHiddenUnicode(str: string): string[] {
    const hiddenChars: string[] = [];
    const hiddenPatterns = [
      '\u200B', // Zero-width space
      '\u200C', // Zero-width non-joiner
      '\u200D', // Zero-width joiner
      '\u2060', // Word joiner
      '\u2061', // Function application
      '\u2062', // Invisible times
      '\u2063', // Invisible separator
      '\u2064', // Invisible plus
      '\uFEFF', // Zero-width no-break space (BOM)
      '\u00AD', // Soft hyphen
      '\u034F', // Combining grapheme joiner
      '\u061C', // Arabic letter mark
      '\u115F', // Hangul choseong filler
      '\u1160', // Hangul jungseong filler
      '\u17B4', // Khmer vowel inherent aq
      '\u17B5', // Khmer vowel inherent aa
      '\u180E', // Mongolian vowel separator
    ];

    for (const char of str) {
      if (hiddenPatterns.includes(char)) {
        hiddenChars.push(char);
      }
    }

    return hiddenChars;
  }

  /**
   * Check for common typosquatting patterns
   */
  private hasTyposquatPattern(suspect: string, legitimate: string): boolean {
    // Character substitution (0 for o, 1 for l, etc.)
    const substitutions: Record<string, string[]> = {
      'o': ['0'],
      'l': ['1', 'i'],
      'i': ['1', 'l'],
      'e': ['3'],
      'a': ['4', '@'],
      's': ['5', '$'],
      'g': ['9', 'q'],
      'b': ['8'],
    };

    // Check if suspect is legitimate with common substitutions
    let normalized = suspect;
    for (const [char, subs] of Object.entries(substitutions)) {
      for (const sub of subs) {
        normalized = normalized.replace(new RegExp(sub, 'g'), char);
      }
    }
    if (normalized === legitimate) return true;

    // Check for doubled characters (githubb, slackk)
    const deduped = suspect.replace(/(.)\1+/g, '$1');
    if (deduped === legitimate) return true;

    // Check for prefix/suffix additions (xgithub, githubx, my-github)
    if (suspect.includes(legitimate) && suspect !== legitimate) return true;

    return false;
  }

  /**
   * Calculate Shannon entropy of a string
   */
  private calculateEntropy(str: string): number {
    const len = str.length;
    if (len === 0) return 0;

    const frequencies: Record<string, number> = {};
    for (const char of str) {
      frequencies[char] = (frequencies[char] || 0) + 1;
    }

    let entropy = 0;
    for (const count of Object.values(frequencies)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  /**
   * Calculate Levenshtein distance between two strings
   */
  private levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];
    
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }
    
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }
    
    return matrix[b.length][a.length];
  }

  /**
   * Create a location object
   */
  private createLocation(content: string, start: number, length: number): IssueLocation {
    const end = start + length;
    const lines = content.substring(0, start).split('\n');
    const line = lines.length;
    const column = lines[lines.length - 1].length + 1;
    return { start, end, line, column };
  }

  /**
   * Truncate string for display
   */
  private truncate(str: string, maxLength: number = 100): string {
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength) + '...';
  }

  /**
   * Redact a secret for safe display
   */
  private redactSecret(secret: string): string {
    if (secret.length <= 8) return '****';
    const visibleStart = Math.min(4, Math.floor(secret.length * 0.15));
    const visibleEnd = Math.min(4, Math.floor(secret.length * 0.15));
    return `${secret.substring(0, visibleStart)}${'*'.repeat(8)}${secret.substring(secret.length - visibleEnd)}`;
  }

  // ============================================================================
  // Public Utility Methods
  // ============================================================================

  /**
   * Parse and validate an MCP manifest
   */
  static parseManifest(content: string): McpServerManifest | null {
    try {
      const parsed = JSON.parse(content);
      if (parsed.name || parsed.tools || parsed.resources) {
        return parsed as McpServerManifest;
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Analyze capabilities of a manifest
   */
  static analyzeCapabilities(manifest: McpServerManifest): McpCapabilities {
    const capabilities: McpCapabilities = {
      network: false,
      filesystem: false,
      execution: false,
      environment: false,
      database: false,
      crypto: false
    };

    for (const tool of manifest.tools || []) {
      const combined = `${tool.name} ${tool.description || ''}`.toLowerCase();
      
      for (const { pattern, capability } of DANGEROUS_CAPABILITY_PATTERNS) {
        if (pattern.test(combined)) {
          capabilities[capability as keyof McpCapabilities] = true;
        }
      }
    }

    return capabilities;
  }

  /**
   * Get risk level based on capabilities
   */
  static getRiskLevel(capabilities: McpCapabilities): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
    if (capabilities.execution) return 'CRITICAL';
    if (capabilities.filesystem && capabilities.network) return 'HIGH';
    if (capabilities.filesystem || capabilities.network || capabilities.environment) return 'MEDIUM';
    return 'LOW';
  }
}

export default McpServerAnalyzer;
