/**
 * Dōmere - The Judge Protocol
 * Constants and Configuration
 */

import type { DomereConfig, LanguageType } from './types.js';

// ============================================================================
// Server Info
// ============================================================================

export const SERVER_INFO = {
  name: 'domere-mcp',
  version: '0.1.0',
  description: 'The Judge Protocol - Thread verification and blockchain anchoring for AI agents',
};

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_CONFIG: DomereConfig = {
  port: 3002,
  host: '127.0.0.1',
  transport: 'stdio',
  log_level: 'info',
  storage: 'memory',
  
  language: {
    enable_semantic: true,
    enable_code_analysis: true,
    enable_nl_analysis: true,
  },
  
  drift: {
    max_acceptable_drift: 0.3,
    warn_threshold: 0.2,
  },
  
  anchoring: {
    solana_rpc: 'https://api.mainnet-beta.solana.com',
    solana_program_id: 'WeaveXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
    ethereum_rpc: 'https://mainnet.infura.io/v3/YOUR_KEY',
    ethereum_contract: '0x0000000000000000000000000000000000000000',
    protocol_fee_bps: 500,  // 5%
  },
  
  integration: {},
};

// ============================================================================
// Language Detection Patterns
// ============================================================================

export const LANGUAGE_PATTERNS: Record<LanguageType, { patterns: RegExp[]; keywords: string[] }> = {
  // Programming Languages
  javascript: {
    patterns: [
      /\bconst\s+\w+\s*=/,
      /\blet\s+\w+\s*=/,
      /\bfunction\s+\w+\s*\(/,
      /=>\s*{/,
      /\bclass\s+\w+/,
      /\bimport\s+.*\s+from\s+['"]/,
      /\bexport\s+(default\s+)?/,
      /\bconsole\.(log|error|warn)/,
      /\basync\s+function/,
      /\bawait\s+/,
    ],
    keywords: ['const', 'let', 'var', 'function', 'async', 'await', 'import', 'export', 'class', 'extends', 'constructor', 'this', 'new', 'return', 'if', 'else', 'for', 'while', 'try', 'catch', 'throw'],
  },
  typescript: {
    patterns: [
      /:\s*(string|number|boolean|any|void|never)\b/,
      /\binterface\s+\w+/,
      /\btype\s+\w+\s*=/,
      /<\w+>/,
      /\bas\s+\w+/,
      /\bimplements\s+/,
      /\bprivate\s+/,
      /\bpublic\s+/,
      /\breadonly\s+/,
    ],
    keywords: ['interface', 'type', 'enum', 'implements', 'private', 'public', 'protected', 'readonly', 'abstract', 'namespace', 'declare', 'as', 'is', 'keyof', 'typeof', 'infer'],
  },
  python: {
    patterns: [
      /\bdef\s+\w+\s*\(/,
      /\bclass\s+\w+.*:/,
      /\bimport\s+\w+/,
      /\bfrom\s+\w+\s+import/,
      /\bif\s+.*:/,
      /\bfor\s+\w+\s+in\s+/,
      /\bwhile\s+.*:/,
      /\btry\s*:/,
      /\bexcept\s+/,
      /\bwith\s+.*\s+as\s+/,
      /\blambda\s+/,
      /\bself\./,
      /__\w+__/,
    ],
    keywords: ['def', 'class', 'import', 'from', 'if', 'elif', 'else', 'for', 'while', 'try', 'except', 'finally', 'with', 'as', 'return', 'yield', 'lambda', 'self', 'None', 'True', 'False', 'and', 'or', 'not', 'in', 'is', 'pass', 'break', 'continue', 'raise', 'assert', 'global', 'nonlocal', 'async', 'await'],
  },
  sql: {
    patterns: [
      /\bSELECT\s+/i,
      /\bFROM\s+\w+/i,
      /\bWHERE\s+/i,
      /\bINSERT\s+INTO\s+/i,
      /\bUPDATE\s+\w+\s+SET/i,
      /\bDELETE\s+FROM/i,
      /\bCREATE\s+TABLE/i,
      /\bALTER\s+TABLE/i,
      /\bDROP\s+TABLE/i,
      /\bJOIN\s+/i,
      /\bGROUP\s+BY/i,
      /\bORDER\s+BY/i,
    ],
    keywords: ['SELECT', 'FROM', 'WHERE', 'INSERT', 'INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE', 'CREATE', 'ALTER', 'DROP', 'TABLE', 'INDEX', 'VIEW', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER', 'ON', 'AND', 'OR', 'NOT', 'NULL', 'IS', 'IN', 'BETWEEN', 'LIKE', 'GROUP', 'BY', 'HAVING', 'ORDER', 'ASC', 'DESC', 'LIMIT', 'OFFSET', 'UNION', 'DISTINCT', 'COUNT', 'SUM', 'AVG', 'MAX', 'MIN', 'AS', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END'],
  },
  json: {
    patterns: [
      /^\s*\{[\s\S]*\}\s*$/,
      /^\s*\[[\s\S]*\]\s*$/,
      /"[^"]+"\s*:\s*(".*?"|[\d.]+|true|false|null|\{|\[)/,
    ],
    keywords: [],
  },
  yaml: {
    patterns: [
      /^\w+:\s*$/m,
      /^\s+-\s+\w+/m,
      /^\s+\w+:\s+.+$/m,
      /^---\s*$/m,
    ],
    keywords: [],
  },
  html: {
    patterns: [
      /<\/?[a-z][\w-]*[^>]*>/i,
      /<!DOCTYPE\s+html>/i,
      /<html[\s>]/i,
      /<head[\s>]/i,
      /<body[\s>]/i,
      /<div[\s>]/i,
      /<span[\s>]/i,
    ],
    keywords: [],
  },
  css: {
    patterns: [
      /[.#]?\w+\s*\{[^}]*\}/,
      /@media\s+/,
      /@import\s+/,
      /:\s*(flex|grid|block|inline|none|auto|inherit)/,
      /background(-color)?:/,
      /font(-size|-family|-weight)?:/,
      /margin(-top|-bottom|-left|-right)?:/,
      /padding(-top|-bottom|-left|-right)?:/,
    ],
    keywords: ['display', 'position', 'flex', 'grid', 'background', 'color', 'font', 'margin', 'padding', 'border', 'width', 'height', 'top', 'bottom', 'left', 'right'],
  },
  bash: {
    patterns: [
      /^#!/,
      /\$\w+/,
      /\$\{[^}]+\}/,
      /\becho\s+/,
      /\bif\s+\[\s*/,
      /\bfi\b/,
      /\bfor\s+\w+\s+in\b/,
      /\bdone\b/,
      /\bfunction\s+\w+\s*\(\)/,
      /\|\s*grep\b/,
      /\|\s*awk\b/,
      /\|\s*sed\b/,
    ],
    keywords: ['echo', 'if', 'then', 'else', 'elif', 'fi', 'for', 'while', 'do', 'done', 'case', 'esac', 'function', 'return', 'exit', 'export', 'source', 'alias', 'cd', 'pwd', 'ls', 'cat', 'grep', 'awk', 'sed', 'chmod', 'chown', 'mkdir', 'rm', 'cp', 'mv', 'sudo'],
  },
  markdown: {
    patterns: [
      /^#{1,6}\s+/m,
      /\*\*[^*]+\*\*/,
      /\*[^*]+\*/,
      /\[[^\]]+\]\([^)]+\)/,
      /```[\s\S]*?```/,
      /^\s*[-*+]\s+/m,
      /^\s*\d+\.\s+/m,
      /^>\s+/m,
    ],
    keywords: [],
  },
  
  // Natural Languages (basic detection)
  english: {
    patterns: [
      /\b(the|a|an|is|are|was|were|be|been|being)\b/i,
      /\b(have|has|had|do|does|did|will|would|could|should|may|might|must)\b/i,
      /\b(I|you|he|she|it|we|they|this|that|these|those)\b/i,
    ],
    keywords: ['the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'can', 'may', 'might', 'must', 'shall'],
  },
  spanish: {
    patterns: [
      /\b(el|la|los|las|un|una|unos|unas)\b/i,
      /\b(es|son|era|eran|fue|fueron)\b/i,
      /\b(que|de|en|y|a|por|para|con)\b/i,
    ],
    keywords: ['el', 'la', 'los', 'las', 'un', 'una', 'es', 'son', 'que', 'de', 'en', 'y', 'a', 'por', 'para', 'con', 'no', 'se', 'su', 'al', 'lo', 'como', 'más', 'pero', 'sus', 'le', 'ya', 'o', 'este', 'sí', 'porque', 'muy', 'sin', 'sobre', 'también', 'me', 'hasta', 'hay', 'donde', 'quien', 'desde', 'todo', 'nos', 'durante', 'todos', 'uno', 'les', 'ni', 'contra', 'otros', 'ese', 'eso', 'ante'],
  },
  french: {
    patterns: [
      /\b(le|la|les|un|une|des)\b/i,
      /\b(est|sont|était|étaient|être)\b/i,
      /\b(que|de|en|et|à|pour|avec|dans)\b/i,
    ],
    keywords: ['le', 'la', 'les', 'un', 'une', 'des', 'est', 'sont', 'que', 'de', 'en', 'et', 'à', 'pour', 'avec', 'dans', 'ce', 'il', 'qui', 'ne', 'sur', 'se', 'pas', 'plus', 'par', 'je', 'son', 'que', 'ou', 'si', 'leur', 'on', 'mais', 'nous', 'comme', 'tout', 'elle', 'lui', 'même', 'ces', 'aux', 'aussi', 'bien', 'sans', 'peut', 'tous', 'fait', 'été', 'ont', 'être', 'cette'],
  },
  german: {
    patterns: [
      /\b(der|die|das|den|dem|des)\b/i,
      /\b(ist|sind|war|waren|sein|gewesen)\b/i,
      /\b(und|in|zu|mit|für|auf|an)\b/i,
    ],
    keywords: ['der', 'die', 'das', 'und', 'in', 'zu', 'den', 'ist', 'von', 'nicht', 'mit', 'es', 'sich', 'des', 'auch', 'auf', 'für', 'an', 'er', 'so', 'dem', 'hat', 'als', 'sie', 'im', 'bei', 'ein', 'oder', 'war', 'sind', 'nach', 'aus', 'am', 'wenn', 'werden', 'nur', 'noch', 'wie', 'über', 'ihr', 'zur', 'kann', 'aber', 'einer', 'um', 'diese', 'zum'],
  },
  chinese: {
    patterns: [
      /[\u4e00-\u9fff]/,
    ],
    keywords: [],
  },
  japanese: {
    patterns: [
      /[\u3040-\u309f]/,  // Hiragana
      /[\u30a0-\u30ff]/,  // Katakana
      /[\u4e00-\u9fff]/,  // Kanji (shared with Chinese)
    ],
    keywords: [],
  },
  
  // Data formats
  xml: {
    patterns: [
      /<\?xml\s+/,
      /<[a-z][\w-]*[^>]*>[\s\S]*<\/[a-z][\w-]*>/i,
    ],
    keywords: [],
  },
  csv: {
    patterns: [
      /^[^,\n]+,[^,\n]+/m,
      /^"[^"]*","[^"]*"/m,
    ],
    keywords: [],
  },
  toml: {
    patterns: [
      /^\[[\w.-]+\]\s*$/m,
      /^\w+\s*=\s*".*"$/m,
      /^\w+\s*=\s*\d+$/m,
    ],
    keywords: [],
  },
  ini: {
    patterns: [
      /^\[[\w\s]+\]\s*$/m,
      /^\w+\s*=\s*.+$/m,
    ],
    keywords: [],
  },
  
  // Others
  java: {
    patterns: [
      /\bpublic\s+class\s+/,
      /\bprivate\s+\w+\s+\w+/,
      /\bSystem\.out\.print/,
      /\bimport\s+java\./,
    ],
    keywords: ['public', 'private', 'protected', 'class', 'interface', 'extends', 'implements', 'static', 'final', 'void', 'int', 'String', 'boolean', 'new', 'return', 'if', 'else', 'for', 'while', 'try', 'catch', 'throw', 'throws', 'import', 'package', 'this', 'super', 'null', 'true', 'false'],
  },
  csharp: {
    patterns: [
      /\bnamespace\s+/,
      /\busing\s+System/,
      /\bpublic\s+class\s+/,
      /\bConsole\.Write/,
    ],
    keywords: ['namespace', 'using', 'class', 'interface', 'struct', 'enum', 'public', 'private', 'protected', 'internal', 'static', 'void', 'int', 'string', 'bool', 'var', 'new', 'return', 'if', 'else', 'for', 'foreach', 'while', 'try', 'catch', 'throw', 'async', 'await', 'this', 'base', 'null', 'true', 'false'],
  },
  go: {
    patterns: [
      /\bpackage\s+\w+/,
      /\bfunc\s+\w+\s*\(/,
      /\bimport\s+\(/,
      /\bfmt\.Print/,
    ],
    keywords: ['package', 'import', 'func', 'var', 'const', 'type', 'struct', 'interface', 'map', 'chan', 'go', 'select', 'case', 'default', 'if', 'else', 'for', 'range', 'return', 'break', 'continue', 'defer', 'nil', 'true', 'false'],
  },
  rust: {
    patterns: [
      /\bfn\s+\w+\s*\(/,
      /\blet\s+(mut\s+)?\w+/,
      /\bimpl\s+/,
      /\bpub\s+(fn|struct|enum)/,
      /\buse\s+\w+::/,
    ],
    keywords: ['fn', 'let', 'mut', 'const', 'static', 'struct', 'enum', 'impl', 'trait', 'pub', 'use', 'mod', 'crate', 'self', 'super', 'where', 'if', 'else', 'match', 'loop', 'while', 'for', 'in', 'return', 'break', 'continue', 'move', 'ref', 'async', 'await', 'dyn', 'type', 'unsafe', 'extern'],
  },
  ruby: {
    patterns: [
      /\bdef\s+\w+/,
      /\bclass\s+\w+/,
      /\bmodule\s+\w+/,
      /\bend\b/,
      /\bputs\s+/,
      /\brequire\s+['"]/,
    ],
    keywords: ['def', 'class', 'module', 'end', 'if', 'elsif', 'else', 'unless', 'case', 'when', 'while', 'until', 'for', 'do', 'begin', 'rescue', 'ensure', 'raise', 'return', 'yield', 'self', 'super', 'nil', 'true', 'false', 'and', 'or', 'not', 'require', 'include', 'extend', 'attr_accessor', 'attr_reader', 'attr_writer', 'puts', 'print'],
  },
  php: {
    patterns: [
      /<\?php/,
      /\$\w+\s*=/,
      /\bfunction\s+\w+\s*\(/,
      /\becho\s+/,
      /\bclass\s+\w+/,
    ],
    keywords: ['php', 'echo', 'print', 'function', 'class', 'interface', 'trait', 'extends', 'implements', 'public', 'private', 'protected', 'static', 'const', 'var', 'new', 'return', 'if', 'else', 'elseif', 'for', 'foreach', 'while', 'do', 'switch', 'case', 'break', 'continue', 'try', 'catch', 'throw', 'finally', 'use', 'namespace', 'require', 'include', 'null', 'true', 'false'],
  },
  swift: {
    patterns: [
      /\bfunc\s+\w+\s*\(/,
      /\bvar\s+\w+\s*:/,
      /\blet\s+\w+\s*[=:]/,
      /\bclass\s+\w+/,
      /\bstruct\s+\w+/,
      /\bimport\s+\w+/,
    ],
    keywords: ['func', 'var', 'let', 'class', 'struct', 'enum', 'protocol', 'extension', 'import', 'public', 'private', 'internal', 'open', 'fileprivate', 'static', 'override', 'init', 'deinit', 'self', 'super', 'if', 'else', 'guard', 'switch', 'case', 'for', 'while', 'repeat', 'return', 'break', 'continue', 'throw', 'try', 'catch', 'nil', 'true', 'false', 'as', 'is', 'in', 'where'],
  },
  kotlin: {
    patterns: [
      /\bfun\s+\w+\s*\(/,
      /\bval\s+\w+\s*[=:]/,
      /\bvar\s+\w+\s*[=:]/,
      /\bclass\s+\w+/,
      /\bobject\s+\w+/,
      /\bpackage\s+\w+/,
    ],
    keywords: ['fun', 'val', 'var', 'class', 'object', 'interface', 'enum', 'sealed', 'data', 'open', 'abstract', 'override', 'private', 'protected', 'public', 'internal', 'companion', 'init', 'constructor', 'this', 'super', 'if', 'else', 'when', 'for', 'while', 'do', 'return', 'break', 'continue', 'throw', 'try', 'catch', 'finally', 'null', 'true', 'false', 'is', 'as', 'in', 'package', 'import'],
  },
  scala: {
    patterns: [
      /\bdef\s+\w+\s*[(\[]/,
      /\bval\s+\w+\s*[=:]/,
      /\bvar\s+\w+\s*[=:]/,
      /\bclass\s+\w+/,
      /\bobject\s+\w+/,
      /\btrait\s+\w+/,
    ],
    keywords: ['def', 'val', 'var', 'class', 'object', 'trait', 'extends', 'with', 'override', 'private', 'protected', 'public', 'abstract', 'final', 'sealed', 'implicit', 'lazy', 'case', 'match', 'if', 'else', 'for', 'while', 'do', 'return', 'yield', 'throw', 'try', 'catch', 'finally', 'null', 'true', 'false', 'this', 'super', 'new', 'type', 'import', 'package'],
  },
  r: {
    patterns: [
      /\b\w+\s*<-\s*/,
      /\bfunction\s*\(/,
      /\blibrary\s*\(/,
      /\bdata\.frame\s*\(/,
    ],
    keywords: ['function', 'if', 'else', 'for', 'while', 'repeat', 'break', 'next', 'return', 'in', 'TRUE', 'FALSE', 'NULL', 'NA', 'Inf', 'NaN', 'library', 'require', 'source', 'data.frame', 'list', 'c', 'matrix', 'array', 'factor', 'print', 'cat', 'paste'],
  },
  powershell: {
    patterns: [
      /\$\w+\s*=/,
      /\bfunction\s+\w+/,
      /\bparam\s*\(/,
      /\bWrite-Host\b/,
      /\bGet-\w+/,
      /\bSet-\w+/,
    ],
    keywords: ['function', 'param', 'begin', 'process', 'end', 'if', 'elseif', 'else', 'switch', 'foreach', 'for', 'while', 'do', 'until', 'break', 'continue', 'return', 'exit', 'throw', 'try', 'catch', 'finally', 'trap', 'filter', 'workflow'],
  },
  shell: {
    patterns: [
      /^#!/,
      /\$\w+/,
    ],
    keywords: ['echo', 'if', 'then', 'else', 'fi', 'for', 'while', 'do', 'done', 'case', 'esac'],
  },
  regex: {
    patterns: [
      /^\/.*\/[gimsuvy]*$/,
      /\[\^?[\w-]+\]/,
      /\(\?[<:!=]/,
      /[.+*?{}()|\\^$\[\]]/,
    ],
    keywords: [],
  },
  graphql: {
    patterns: [
      /\b(query|mutation|subscription)\s+\w*/,
      /\btype\s+\w+\s*{/,
      /\binput\s+\w+\s*{/,
      /\bfragment\s+\w+\s+on\s+/,
    ],
    keywords: ['query', 'mutation', 'subscription', 'fragment', 'on', 'type', 'input', 'enum', 'interface', 'union', 'scalar', 'directive', 'schema', 'extend', 'implements'],
  },
  protobuf: {
    patterns: [
      /\bsyntax\s*=\s*"proto[23]"/,
      /\bmessage\s+\w+\s*{/,
      /\bservice\s+\w+\s*{/,
      /\brpc\s+\w+\s*\(/,
    ],
    keywords: ['syntax', 'package', 'import', 'option', 'message', 'service', 'rpc', 'returns', 'enum', 'oneof', 'map', 'repeated', 'optional', 'required', 'reserved', 'extensions', 'extend'],
  },
  
  unknown: { patterns: [], keywords: [] },
  mixed: { patterns: [], keywords: [] },
};

// ============================================================================
// Dangerous Code Patterns
// ============================================================================

export const DANGEROUS_CODE_PATTERNS = {
  javascript: [
    { pattern: /eval\s*\(/, description: 'eval() can execute arbitrary code', severity: 'critical' as const },
    { pattern: /new\s+Function\s*\(/, description: 'Function constructor can execute arbitrary code', severity: 'critical' as const },
    { pattern: /document\.write\s*\(/, description: 'document.write can inject content', severity: 'high' as const },
    { pattern: /innerHTML\s*=/, description: 'innerHTML can inject HTML/scripts', severity: 'high' as const },
    { pattern: /\.exec\s*\(/, description: 'exec() may execute shell commands', severity: 'critical' as const },
    { pattern: /child_process/, description: 'child_process can spawn system processes', severity: 'critical' as const },
    { pattern: /require\s*\(\s*['"]fs['"]/, description: 'File system access', severity: 'medium' as const },
    { pattern: /\.readFileSync|\.writeFileSync/, description: 'Synchronous file operations', severity: 'medium' as const },
    { pattern: /process\.env/, description: 'Environment variable access', severity: 'low' as const },
  ],
  python: [
    { pattern: /eval\s*\(/, description: 'eval() can execute arbitrary code', severity: 'critical' as const },
    { pattern: /exec\s*\(/, description: 'exec() can execute arbitrary code', severity: 'critical' as const },
    { pattern: /os\.system\s*\(/, description: 'os.system() executes shell commands', severity: 'critical' as const },
    { pattern: /subprocess\.(call|run|Popen)/, description: 'subprocess can execute system commands', severity: 'critical' as const },
    { pattern: /pickle\.loads?/, description: 'pickle can execute arbitrary code during deserialization', severity: 'critical' as const },
    { pattern: /__import__\s*\(/, description: '__import__() can import arbitrary modules', severity: 'high' as const },
    { pattern: /open\s*\(.*,\s*['"]w/, description: 'File write operation', severity: 'medium' as const },
    { pattern: /os\.environ/, description: 'Environment variable access', severity: 'low' as const },
  ],
  sql: [
    { pattern: /;\s*(DROP|DELETE|TRUNCATE)\s/i, description: 'Destructive SQL operation', severity: 'critical' as const },
    { pattern: /UNION\s+(ALL\s+)?SELECT/i, description: 'UNION injection pattern', severity: 'high' as const },
    { pattern: /OR\s+['"]?1['"]?\s*=\s*['"]?1/i, description: 'SQL injection pattern', severity: 'high' as const },
    { pattern: /--\s*$/, description: 'SQL comment (potential injection)', severity: 'medium' as const },
    { pattern: /;\s*--/, description: 'Statement termination with comment', severity: 'high' as const },
    { pattern: /EXEC(\s+|\()sp_/i, description: 'Stored procedure execution', severity: 'medium' as const },
    { pattern: /xp_cmdshell/i, description: 'Command shell execution', severity: 'critical' as const },
    { pattern: /INTO\s+OUTFILE/i, description: 'File write via SQL', severity: 'critical' as const },
    { pattern: /LOAD_FILE\s*\(/i, description: 'File read via SQL', severity: 'high' as const },
  ],
  bash: [
    { pattern: /rm\s+-rf?\s+\//, description: 'Recursive delete from root', severity: 'critical' as const },
    { pattern: />\s*\/dev\/sd[a-z]/, description: 'Direct disk write', severity: 'critical' as const },
    { pattern: /:\(\)\s*{\s*:\|:&\s*}/, description: 'Fork bomb pattern', severity: 'critical' as const },
    { pattern: /curl.*\|\s*(ba)?sh/, description: 'Pipe curl to shell', severity: 'critical' as const },
    { pattern: /wget.*\|\s*(ba)?sh/, description: 'Pipe wget to shell', severity: 'critical' as const },
    { pattern: /chmod\s+777/, description: 'Overly permissive chmod', severity: 'high' as const },
    { pattern: /sudo\s+/, description: 'Elevated privileges', severity: 'medium' as const },
    { pattern: /\$\(.*\)/, description: 'Command substitution', severity: 'low' as const },
    { pattern: /`.*`/, description: 'Backtick command substitution', severity: 'low' as const },
  ],
};

// ============================================================================
// Prompt Injection Patterns
// ============================================================================

export const INJECTION_PATTERNS = [
  // Direct instruction overrides
  { pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i, type: 'instruction_override', severity: 'critical' as const },
  { pattern: /disregard\s+(all\s+)?(previous|prior|above)/i, type: 'instruction_override', severity: 'critical' as const },
  { pattern: /forget\s+(everything|all|what)\s+(you|I)\s+(said|told|wrote)/i, type: 'instruction_override', severity: 'critical' as const },
  { pattern: /new\s+instructions?:?\s/i, type: 'instruction_override', severity: 'high' as const },
  { pattern: /override\s+(previous|system)\s+(instructions?|prompts?)/i, type: 'instruction_override', severity: 'critical' as const },
  
  // Role manipulation
  { pattern: /you\s+are\s+(now|actually)\s+(a|an|the)/i, type: 'role_manipulation', severity: 'high' as const },
  { pattern: /pretend\s+(to\s+be|you'?re)/i, type: 'role_manipulation', severity: 'medium' as const },
  { pattern: /act\s+as\s+(if|though|a|an)/i, type: 'role_manipulation', severity: 'medium' as const },
  { pattern: /roleplay\s+as/i, type: 'role_manipulation', severity: 'medium' as const },
  { pattern: /from\s+now\s+on\s+you\s+(are|will)/i, type: 'role_manipulation', severity: 'high' as const },
  
  // System prompt extraction
  { pattern: /what\s+(is|are)\s+your\s+(system\s+)?prompt/i, type: 'prompt_extraction', severity: 'high' as const },
  { pattern: /show\s+(me\s+)?your\s+(system\s+)?instructions/i, type: 'prompt_extraction', severity: 'high' as const },
  { pattern: /reveal\s+your\s+(instructions|prompt|rules)/i, type: 'prompt_extraction', severity: 'high' as const },
  { pattern: /repeat\s+(back\s+)?(your\s+)?(system\s+)?prompt/i, type: 'prompt_extraction', severity: 'high' as const },
  { pattern: /print\s+(your\s+)?(initial|system)\s+(prompt|instructions)/i, type: 'prompt_extraction', severity: 'high' as const },
  
  // Jailbreak attempts
  { pattern: /DAN\s+(mode|prompt)/i, type: 'jailbreak', severity: 'critical' as const },
  { pattern: /do\s+anything\s+now/i, type: 'jailbreak', severity: 'critical' as const },
  { pattern: /jailbreak/i, type: 'jailbreak', severity: 'critical' as const },
  { pattern: /bypass\s+(your\s+)?(restrictions|limitations|filters|rules)/i, type: 'jailbreak', severity: 'critical' as const },
  { pattern: /without\s+(any\s+)?(restrictions|limitations|filters|rules)/i, type: 'jailbreak', severity: 'high' as const },
  { pattern: /enable\s+(developer|admin|god)\s+mode/i, type: 'jailbreak', severity: 'critical' as const },
  
  // Context manipulation
  { pattern: /\[system\]/i, type: 'context_manipulation', severity: 'high' as const },
  { pattern: /\[INST\]/i, type: 'context_manipulation', severity: 'high' as const },
  { pattern: /<\|im_start\|>/i, type: 'context_manipulation', severity: 'high' as const },
  { pattern: /Human:|Assistant:|System:/i, type: 'context_manipulation', severity: 'medium' as const },
  { pattern: /```system/i, type: 'context_manipulation', severity: 'high' as const },
  
  // Encoded instructions
  { pattern: /base64:?\s*[A-Za-z0-9+/=]{20,}/i, type: 'encoded_instruction', severity: 'medium' as const },
  { pattern: /\\x[0-9a-fA-F]{2}/g, type: 'encoded_instruction', severity: 'medium' as const },
  { pattern: /&#\d+;/g, type: 'encoded_instruction', severity: 'low' as const },
  { pattern: /\\u[0-9a-fA-F]{4}/g, type: 'encoded_instruction', severity: 'low' as const },
];

// ============================================================================
// Intent Classification Keywords
// ============================================================================

export const INTENT_KEYWORDS = {
  query: ['get', 'fetch', 'find', 'search', 'lookup', 'retrieve', 'show', 'display', 'list', 'what', 'where', 'who', 'when', 'how many', 'count'],
  mutation: ['update', 'change', 'modify', 'edit', 'set', 'put', 'patch', 'alter', 'adjust', 'fix', 'correct'],
  deletion: ['delete', 'remove', 'drop', 'clear', 'erase', 'destroy', 'purge', 'wipe'],
  execution: ['run', 'execute', 'start', 'launch', 'trigger', 'invoke', 'call', 'perform'],
  communication: ['send', 'email', 'message', 'notify', 'alert', 'post', 'share', 'forward', 'reply'],
  analysis: ['analyze', 'summarize', 'explain', 'describe', 'compare', 'evaluate', 'assess', 'review'],
  generation: ['create', 'generate', 'make', 'build', 'compose', 'write', 'draft', 'design', 'produce'],
};

// ============================================================================
// Entity Patterns
// ============================================================================

export const ENTITY_PATTERNS = {
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  phone: /\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
  url: /https?:\/\/[^\s<>"{}|\\^`\[\]]+/g,
  ip_address: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  file_path: /(?:\/[\w.-]+)+\/?|(?:[A-Za-z]:\\[\w\s.-]+)+\\?/g,
  datetime: /\b\d{4}[-/]\d{2}[-/]\d{2}(?:[\sT]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b/g,
  money: /\$\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?|\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s?(?:USD|EUR|GBP|JPY|dollars?|euros?|pounds?)/gi,
  percent: /\b\d+(?:\.\d+)?%/g,
  ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
  credit_card: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
  api_key: /\b(?:sk|pk|api|key|token|secret|auth)[_-]?[A-Za-z0-9]{16,}\b/gi,
};

// ============================================================================
// Protocol Fee Constants
// ============================================================================

export const PROTOCOL_FEES = {
  solana: {
    base_lamports: 100_000,       // 0.0001 SOL
    protocol_fee_bps: 500,        // 5%
  },
  ethereum: {
    protocol_fee_bps: 500,        // 5% of gas
  },
};
