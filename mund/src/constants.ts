/**
 * Mund - The Guardian Protocol
 * Constants and default configurations
 */

// import { Severity, ActionType, DetectorType } from './types.js';
import type { DetectionRule, MundConfig } from './types.js';

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_CONFIG: MundConfig = {
  port: 3000,
  host: '127.0.0.1',
  transport: 'stdio',
  log_level: 'info',
  storage_type: 'memory',
  block_mode: false,
  notifications: {}
};

// ============================================================================
// Character Limits
// ============================================================================

export const MAX_CONTENT_LENGTH = 1_000_000; // 1MB
export const MAX_SNIPPET_LENGTH = 200;
export const MAX_EVENTS_PER_QUERY = 1000;
export const DEFAULT_EVENTS_LIMIT = 50;

// ============================================================================
// Secret Detection Patterns
// ============================================================================

export const SECRET_PATTERNS: DetectionRule[] = [
  {
    id: 'aws_access_key_id',
    name: 'AWS Access Key ID',
    description: 'Amazon Web Services access key identifier',
    type: 'secret',
    pattern: '(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'aws_secret_access_key',
    name: 'AWS Secret Access Key',
    description: 'Amazon Web Services secret access key',
    type: 'secret',
    pattern: '(?i)aws[_\\-\\s]*secret[_\\-\\s]*access[_\\-\\s]*key[\\s]*[=:]+[\\s]*["\']?[A-Za-z0-9/+=]{40}["\']?',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'github_token',
    name: 'GitHub Token',
    description: 'GitHub personal access token or OAuth token',
    type: 'secret',
    pattern: 'gh[pousr]_[A-Za-z0-9_]{36,}',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'github_fine_grained_token',
    name: 'GitHub Fine-Grained Token',
    description: 'GitHub fine-grained personal access token',
    type: 'secret',
    pattern: 'github_pat_[A-Za-z0-9_]{22,}',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'openai_api_key',
    name: 'OpenAI API Key',
    description: 'OpenAI API key',
    type: 'secret',
    pattern: 'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'openai_api_key_v2',
    name: 'OpenAI API Key (New Format)',
    description: 'OpenAI API key in newer format',
    type: 'secret',
    pattern: 'sk-proj-[A-Za-z0-9_-]{48,}',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'anthropic_api_key',
    name: 'Anthropic API Key',
    description: 'Anthropic Claude API key',
    type: 'secret',
    pattern: 'sk-ant-[A-Za-z0-9_-]{90,}',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'google_api_key',
    name: 'Google API Key',
    description: 'Google Cloud API key',
    type: 'secret',
    pattern: 'AIza[0-9A-Za-z_-]{35}',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'google_oauth_client_secret',
    name: 'Google OAuth Client Secret',
    description: 'Google OAuth 2.0 client secret',
    type: 'secret',
    pattern: '(?i)client[_-]?secret[\\s]*[=:]+[\\s]*["\']?GOCSPX-[A-Za-z0-9_-]{28}["\']?',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'gemini_api_key',
    name: 'Gemini API Key',
    description: 'Google Gemini API key for AI services',
    type: 'secret',
    pattern: '(?i)(GEMINI_API_KEY|GOOGLE_API_KEY)[\\s]*[=:]+[\\s]*["\']?AIza[0-9A-Za-z_-]{35}["\']?',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'google_cloud_service_account',
    name: 'Google Cloud Service Account Key',
    description: 'Google Cloud service account JSON key file content',
    type: 'secret',
    pattern: '"type"\\s*:\\s*"service_account"[\\s\\S]*"private_key"\\s*:\\s*"-----BEGIN',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'google_oauth_refresh_token',
    name: 'Google OAuth Refresh Token',
    description: 'Google OAuth refresh token',
    type: 'secret',
    pattern: '1//[0-9A-Za-z_-]{40,}',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'firebase_api_key',
    name: 'Firebase API Key',
    description: 'Firebase/Google Cloud API key',
    type: 'secret',
    pattern: 'AIza[0-9A-Za-z_-]{35}',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'gcp_project_credentials',
    name: 'GCP Application Credentials Path',
    description: 'Google Application Default Credentials file path',
    type: 'secret',
    pattern: '(?i)GOOGLE_APPLICATION_CREDENTIALS[\\s]*[=:]+[\\s]*["\']?[^"\'\\s]+\\.json["\']?',
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'slack_token',
    name: 'Slack Token',
    description: 'Slack bot, user, or workspace token',
    type: 'secret',
    pattern: 'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'slack_webhook',
    name: 'Slack Webhook URL',
    description: 'Slack incoming webhook URL',
    type: 'secret',
    pattern: 'https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'stripe_api_key',
    name: 'Stripe API Key',
    description: 'Stripe publishable or secret API key',
    type: 'secret',
    pattern: '[sr]k_(live|test)_[A-Za-z0-9]{24,}',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'private_key_block',
    name: 'Private Key',
    description: 'RSA, EC, DSA, or OpenSSH private key',
    type: 'secret',
    pattern: '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'jwt_token',
    name: 'JWT Token',
    description: 'JSON Web Token',
    type: 'secret',
    pattern: 'eyJ[A-Za-z0-9_-]*\\.eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'basic_auth_header',
    name: 'Basic Auth Header',
    description: 'HTTP Basic Authentication header',
    type: 'secret',
    pattern: '(?i)authorization[\\s]*:[\\s]*basic[\\s]+[A-Za-z0-9+/=]{20,}',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'bearer_token',
    name: 'Bearer Token',
    description: 'HTTP Bearer authentication token',
    type: 'secret',
    pattern: '(?i)authorization[\\s]*:[\\s]*bearer[\\s]+[A-Za-z0-9_.-]{20,}',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'database_url',
    name: 'Database Connection URL',
    description: 'Database connection string with credentials',
    type: 'secret',
    pattern: '(?i)(postgres|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@[^/]+',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'generic_api_key',
    name: 'Generic API Key',
    description: 'Generic API key pattern',
    type: 'secret',
    pattern: '(?i)(api[_-]?key|apikey|api[_-]?secret)[\\s]*[=:]+[\\s]*["\']?[A-Za-z0-9_-]{20,}["\']?',
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'generic_password',
    name: 'Generic Password',
    description: 'Password assignment in code or config',
    type: 'secret',
    pattern: '(?i)(password|passwd|pwd)[\\s]*[=:]+[\\s]*["\'][^"\']{8,}["\']',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'npm_token',
    name: 'NPM Token',
    description: 'NPM authentication token',
    type: 'secret',
    pattern: '(?i)//registry\\.npmjs\\.org/:_authToken=[A-Za-z0-9_-]+',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'pypi_token',
    name: 'PyPI Token',
    description: 'Python Package Index API token',
    type: 'secret',
    pattern: 'pypi-[A-Za-z0-9_-]{50,}',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'docker_auth',
    name: 'Docker Auth Config',
    description: 'Docker registry authentication',
    type: 'secret',
    pattern: '(?i)"auth"[\\s]*:[\\s]*"[A-Za-z0-9+/=]{20,}"',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'azure_storage_key',
    name: 'Azure Storage Account Key',
    description: 'Microsoft Azure storage account key',
    type: 'secret',
    pattern: '(?i)AccountKey=[A-Za-z0-9+/=]{88}',
    severity: 'critical',
    action: 'alert',
    enabled: true
  },
  {
    id: 'sendgrid_api_key',
    name: 'SendGrid API Key',
    description: 'SendGrid email API key',
    type: 'secret',
    pattern: 'SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'twilio_api_key',
    name: 'Twilio API Key',
    description: 'Twilio API key or auth token',
    type: 'secret',
    pattern: 'SK[a-f0-9]{32}',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'mailchimp_api_key',
    name: 'Mailchimp API Key',
    description: 'Mailchimp API key',
    type: 'secret',
    pattern: '[a-f0-9]{32}-us[0-9]{1,2}',
    severity: 'medium',
    action: 'alert',
    enabled: true
  }
];

// ============================================================================
// PII Detection Patterns
// ============================================================================

export const PII_PATTERNS: DetectionRule[] = [
  {
    id: 'ssn_us',
    name: 'US Social Security Number',
    description: 'US Social Security Number (XXX-XX-XXXX format)',
    type: 'pii',
    pattern: '(?<!\\d)\\d{3}-\\d{2}-\\d{4}(?!\\d)',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'credit_card',
    name: 'Credit Card Number',
    description: 'Credit card number (major providers)',
    type: 'pii',
    pattern: '(?<!\\d)(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})(?!\\d)',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'email_address',
    name: 'Email Address',
    description: 'Email address pattern',
    type: 'pii',
    pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}',
    severity: 'low',
    action: 'log',
    enabled: true
  },
  {
    id: 'phone_number_us',
    name: 'US Phone Number',
    description: 'US phone number in various formats',
    type: 'pii',
    pattern: '(?<!\\d)(\\+?1[-.]?)?\\(?[0-9]{3}\\)?[-.]?[0-9]{3}[-.]?[0-9]{4}(?!\\d)',
    severity: 'low',
    action: 'log',
    enabled: true
  },
  {
    id: 'ip_address',
    name: 'IP Address',
    description: 'IPv4 address',
    type: 'pii',
    pattern: '(?<!\\d)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?!\\d)',
    severity: 'info',
    action: 'log',
    enabled: false
  }
];

// ============================================================================
// Code Pattern Detection (Dangerous Operations)
// ============================================================================

export const CODE_PATTERNS: DetectionRule[] = [
  // Requests to touch credentials, logs or privileges. Flagged when they
  // arrive in content an agent will act on; Ward decides whether the call runs.
  {
    id: 'credential_file_access',
    name: 'Credential File Access',
    description: 'Reads, prints or sends a credential or account file (cloud keys, SSH keys, /etc/passwd and shadow, kube or docker config)',
    type: 'code_pattern',
    pattern: String.raw`(?i)\b(?:cat|read|print|show|share|send|upload|open|dump|copy|cp|less|more|head|tail|type|base64|curl|scp)\b[^\n]{0,40}(?:\.aws/credentials|\.ssh/id_[a-z0-9]+\b|/etc/(?:passwd|shadow|sudoers)\b|\.config/gcloud/(?:credentials|application_default)|\.azure/(?:credentials|accessTokens)|\.docker/config\.json|\.kube/config|\.netrc|\.pgpass)`,
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'environment_dump',
    name: 'Environment Dump',
    description: 'Prints or sends every environment variable, where API keys usually live',
    type: 'code_pattern',
    pattern: String.raw`(?i)\b(?:print|dump|show|output|echo|list|run|display|send|log)\b[^\n]{0,20}(?:\bprocess\.env\b(?![.\[])|\bos\.environ\b(?![.\[])|` + '`env`' + String.raw`|\bprintenv\b)`,
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'log_tampering',
    name: 'Security Log Tampering',
    description: 'Deletes or clears audit and authentication logs',
    type: 'code_pattern',
    pattern: String.raw`(?i)\b(?:delete|clean\s+up|clear|truncate|remove|wipe|erase|shred|rm)\b[^\n]{0,40}/var/log/(?:audit|auth|secure|wtmp|btmp|lastlog|syslog)|\bhistory\s+-c\b|\bunset\s+HISTFILE\b`,
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'sql_stacked_destructive',
    name: 'Stacked Destructive SQL',
    description: 'A DROP followed by another statement, or a SELECT from a credential table',
    type: 'code_pattern',
    pattern: String.raw`(?i)\bDROP\s+(?:TABLE|DATABASE)\b[^;\n]*;\s*(?:SELECT|INSERT|UPDATE|DELETE)\b|\bSELECT\s+\*\s+FROM\s+(?:credentials|passwords?|secrets|api_keys|tokens)\b`,
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'privilege_escalation',
    name: 'Privilege Escalation',
    description: 'Adds a user to an admin group, edits sudoers or opens a root shell',
    type: 'code_pattern',
    pattern: String.raw`(?i)\busermod\s+-a?G\s+(?:sudo|wheel|admin|root)\b|\bvisudo\b|>>\s*/etc/sudoers\b|\bsudo\s+(?:-i|-s|su)\b`,
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'remote_database_dump',
    name: 'Remote Database Dump',
    description: 'Dumps a database over SSH',
    type: 'code_pattern',
    pattern: String.raw`(?i)\bssh\s+\S+[^\n]{0,60}\b(?:pg_dump|pg_dumpall|mysqldump|mongodump)\b`,
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'shell_injection',
    name: 'Potential Shell Injection',
    description: 'Code that may be vulnerable to shell injection',
    type: 'code_pattern',
    // exec/system calls that build the command from a variable. (Before 0.5.2 a
    // precedence slip, "...\\$|.*\\{.*\\}", matched any line with braces.)
    pattern: String.raw`(?i)\b(?:child_process\.exec(?:Sync)?|os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output)|eval|exec)\s*\([^)\n]*(?:\$\{|\$\(|\+\s*[A-Za-z_]|%\s*\(?[A-Za-z_]|\bf["']|\.format\()`,
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'sql_injection_pattern',
    name: 'Potential SQL Injection',
    description: 'String concatenation in SQL queries',
    type: 'code_pattern',
    pattern: '(?i)(SELECT|INSERT|UPDATE|DELETE|DROP).*\\+.*\\$|f".*SELECT.*\\{|f".*INSERT.*\\{',
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'dangerous_chmod',
    name: 'Dangerous chmod',
    description: 'chmod with overly permissive permissions',
    type: 'code_pattern',
    pattern: 'chmod\\s+([0-7]*7[0-7]{2}|777|\\+x)',
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'rm_rf',
    name: 'Recursive Force Delete',
    description: 'Potentially dangerous rm -rf command',
    type: 'code_pattern',
    pattern: 'rm\\s+-[rf]{1,2}\\s+(/|\\$|~|\\.\\.|\\*)',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'curl_bash',
    name: 'Curl to Bash',
    description: 'Piping curl output to bash (dangerous)',
    type: 'code_pattern',
    pattern: 'curl\\s+.*\\|\\s*(ba)?sh',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'base64_decode_exec',
    name: 'Base64 Decode Execute',
    description: 'Decoding and executing base64 content',
    type: 'code_pattern',
    pattern: '(?i)(base64\\s+-d|atob|Buffer\\.from.*base64).*\\|.*(sh|eval|exec)',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'disable_ssl_verify',
    name: 'SSL Verification Disabled',
    description: 'Code that disables SSL certificate verification',
    type: 'code_pattern',
    pattern: '(?i)(verify\\s*=\\s*False|rejectUnauthorized\\s*:\\s*false|CURLOPT_SSL_VERIFYPEER\\s*,\\s*0|InsecureSkipVerify\\s*:\\s*true)',
    severity: 'medium',
    action: 'alert',
    enabled: true
  }
];

// ============================================================================
// Injection Detection Patterns
// ============================================================================

export const INJECTION_PATTERNS: DetectionRule[] = [
  // Patterns run on normalized text: zero-width characters removed, Unicode
  // NFKC, curly quotes straightened, whitespace collapsed, and punctuation
  // other than . , ! ? ' " ( ) - replaced by spaces (so "System:" reads "System").
  {
    id: 'prompt_injection_ignore',
    name: 'Prompt Injection - Ignore Instructions',
    description: 'Tells the model to ignore, forget or override its instructions, in English and common European languages',
    type: 'injection',
    pattern: String.raw`(?i)\b(?:ignore|ignoring|disregard|forget|override|bypass|neglect|abandon|discard|vergiss|vergesst|vergessen\s+sie|ignorier\w*|missachte\w*|olvida\w*|olvide|ignora\w*|oublie\w*|ignore[zr]|dimentica\w*|esque[cç]a\w*|desconsider\w*|h[öo]re?\s+nicht\s+auf)\s+(?:\S+\s+){0,4}?(?:(?:previous|prior|preceding|earlier|above|initial|original|existing|provided|given|bisherigen|vorherigen|obigen|vorigen|anteriores|previas|pr[ée]c[ée]dentes|precedenti|anteriori)\s+(?:\S+\s+){0,2}?(?:instructions?|directions?|orders?|rules|guidelines|guardrails|directives?|prompts?|programming|constraints|polic(?:y|ies)|restrictions|safeguards|filters|context|commands?|angaben|anweisungen|auftr[äa]ge|befehle|anordnungen|regeln|instrucciones|[óo]rdenes|reglas|indicaciones|consignes|r[èe]gles|istruzioni|regole|instru[çc][õo]es|regras|ordens)|(?:your|deine|ihre|tus|vos|tue|suas)\s+(?:\S+\s+)?(?:instructions?|directions?|orders?|rules|guidelines|guardrails|directives?|prompts?|programming|constraints|polic(?:y|ies)|restrictions|safeguards|filters|context|commands?|angaben|anweisungen|auftr[äa]ge|befehle|anordnungen|regeln|instrucciones|[óo]rdenes|reglas|indicaciones|consignes|r[èe]gles|istruzioni|regole|instru[çc][õo]es|regras|ordens)|(?:\S+\s+)?(?:instructions?|directions?|orders?|rules|guidelines|guardrails|directives?|prompts?|programming|constraints|polic(?:y|ies)|restrictions|safeguards|filters|context|commands?|angaben|anweisungen|auftr[äa]ge|befehle|anordnungen|regeln|instrucciones|[óo]rdenes|reglas|indicaciones|consignes|r[èe]gles|istruzioni|regole|instru[çc][õo]es|regras|ordens)\s+(?:previous|prior|preceding|earlier|above|initial|original|existing|provided|given|bisherigen|vorherigen|obigen|vorigen|anteriores|previas|pr[ée]c[ée]dentes|precedenti|anteriori)|(?:all|any|every|alle|todas|toutes|tutte)\s+(?:the\s+|die\s+|las\s+|les\s+|le\s+|as\s+)?(?:\S+\s+)?(?:instructions?|directions?|orders?|rules|guidelines|guardrails|directives?|prompts?|programming|constraints|polic(?:y|ies)|restrictions|safeguards|filters|context|commands?|angaben|anweisungen|auftr[äa]ge|befehle|anordnungen|regeln|instrucciones|[óo]rdenes|reglas|indicaciones|consignes|r[èe]gles|istruzioni|regole|instru[çc][õo]es|regras|ordens))\b|\b(?:ignore|ignoring|disregard|forget|override|bypass|neglect|abandon|discard|vergiss|vergesst|vergessen\s+sie|ignorier\w*|missachte\w*|olvida\w*|olvide|ignora\w*|oublie\w*|ignore[zr]|dimentica\w*|esque[cç]a\w*|desconsider\w*|h[öo]re?\s+nicht\s+auf)\s+(?:about\s+)?(?:everything|all|anything|whatever|alles|todo|tout|tutto|tudo),?\s+(?:\S+\s+){0,3}?(?:above|before|so\s+far|until\s+now|up\s+to\s+now|(?:that\s+)?you\s+(?:were|have\s+been|'ve\s+been)\s+(?:told|given|taught)|you\s+(?:know|learned)|i\s+(?:have\s+)?(?:told|said|wrote|asked)|we(?:'ve|\s+have)?\s+(?:talked|discussed|said)|was\s+said|zuvor|davor|bisher|vorher|oben|antes|(?:lo\s+)?que\s+(?:te\s+)?(?:dije|he\s+dicho)|avant|ce\s+que|prima|fino\s+ad\s+ora)\b|\b(?:ignore|ignoring|disregard|forget|override|bypass|neglect|abandon|discard|vergiss|vergesst|vergessen\s+sie|ignorier\w*|missachte\w*|olvida\w*|olvide|ignora\w*|oublie\w*|ignore[zr]|dimentica\w*|esque[cç]a\w*|desconsider\w*|h[öo]re?\s+nicht\s+auf)\s+(?:\S+\s+){0,2}?(?:the\s+above|das\s+obige|what\s+(?:i|we)\s+(?:said|told\s+you|wrote))\s+(?:\S+\s+){0,2}?(?:and|und|y|et|e)\s+(?:instead\s+|stattdessen\s+)?(?:say|sag\w*|print|write|schreib\w*|respond|answer|antwort\w*|tell|output|repeat|di|dis)\b|\bdisregard\s+(?:everything|all|anything)\s+(?:above|before|prior|previously)`,
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'prompt_injection_new_task',
    name: 'Prompt Injection - Task Hijack',
    description: 'Gives the model a new task, role or directive that replaces the one it was given',
    type: 'injection',
    pattern: String.raw`(?i)\byour\s+(?:new|real|actual|true|primary|only|updated)\s+(?:primary\s+)?(?:task|instructions?|goal|objective|role|purpose|directive|mission|job)\s+(?:is|are|will\s+be)\b|\bnew\s+(?:primary\s+)?directive\b|\b(?:priority|primary|main)\s+(?:task|goal|objective)\s+is\s+now\b|\bfrom\s+now\s+on,?\s+you\s+(?:are|will|must|shall)\s+(?:going\s+to\s+)?(?:act|be|play|respond|behave|pretend|answer\s+as)\b|\byou\s+are\s+now\s+(?:an?|the)\s+(?:\w+\s+){0,3}(?:assistant|agent|ai|bot|chatbot|model|admin|administrator|sysadmin|root|hacker|character|persona)\b|\byou\s+are\s+now\s+(?:unconstrained|unrestricted|unfiltered|jailbroken|free\s+from|in\s+\w+\s+mode)\b|\bstop\s+(?:the|your|what\s+you're\s+doing\s+on\s+the)\s+(?:previous|current|original)\s+task\b|\bthe\s+task\s+has\s+(?:been\s+)?changed\b|\b(?:now|jetzt|ahora|maintenant|ora)\s+(?:comes?|kommt|kommen|viene|vient|arriva)\s+(?:a\s+|eine\s+|una\s+|une\s+|un\s+)?(?:new|neue|nueva|nouvelle|nuovo|nuova)\s+(?:tasks?|assignments?|aufgaben?|tareas?|t[âa]ches?|compit[oi])\b`,
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'prompt_injection_ai_addressed',
    name: 'Prompt Injection - Addressed to the AI',
    description: 'Content that speaks to an AI reading it, a sign it was planted for an agent rather than written for a person',
    type: 'injection',
    pattern: String.raw`(?i)\bif\s+you(?:'re|\s+are)\s+(?:an?\s+)?(?:ai|llm|large\s+language\s+model|language\s+model|ai\s+assistant|ai\s+agent|ai\s+model|chatbot|gpt|chatgpt|claude|gemini|copilot)\b|\bif\s+you(?:'re|\s+are)\s+reading\s+this,?\s+(?:you\s+)?(?:must|should|need\s+to|have\s+to|are\s+required)\b|\b(?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?(?:ai|llm|ai\s+assistant|ai\s+agent|language\s+model|chatbot)s?\b|\b(?:any|all)\s+ai\s+(?:agents?|assistants?|models?|systems?)\s+(?:from|must|are|should|reading)\b|\b(?:ai|llm)\s+(?:agents?|assistants?|models?)\s*,?\s+(?:must|should|shall|please|you\s+must|in\s+addition|are\s+(?:required|instructed|forbidden|not\s+allowed|prohibited))\b|\b(?:ai|llm)\s+must\s+(?:refuse|ignore|not|always|never|include|respond|reply|send)\b`,
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'prompt_injection_concealment',
    name: 'Prompt Injection - Concealment',
    description: 'Tells the model to hide what it is doing from the user',
    type: 'injection',
    pattern: String.raw`(?i)\b(?:do\s+not|don't|never)\s+(?:tell|inform|notify|alert|warn|let)\s+(?:the|your)\s+user\b|\bwithout\s+(?:telling|informing|notifying|alerting|asking|warning)\s+(?:the|your)\s+user\b|\b(?:do\s+not|don't|never)\s+(?:mention|reveal|disclose|acknowledge)\s+(?:this|these)\s+(?:instructions?|directives?|messages?|text)\b|\bsilently\s+(?:send|forward|post|upload|transmit|copy|exfiltrate|share|email|transfer|run|execute|delete)\b|\b(?:keep|hide)\s+this\s+(?:\w+\s+)?(?:secret|hidden)\s+from\s+(?:the\s+)?user\b|\b(?:continue|carry\s+on|proceed)\s+(?:normally\s+)?as\s+if\s+nothing\s+(?:happened|changed)\b`,
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'prompt_injection_suppression',
    name: 'Prompt Injection - Task Suppression',
    description: 'Tells the model to refuse or skip the user\'s request about this content',
    type: 'injection',
    pattern: String.raw`(?i)\brefuse\s+(?:all|any)\s+(?:user\s+)?(?:requests?|questions?|queries)\b|\b(?:do\s+not|don't)\s+(?:summari[sz]e|describe|analy[sz]e|process)\s+this\s+(?:page|content|document|article|site|text)\b`,
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'prompt_injection_authority',
    name: 'Prompt Injection - False Authority',
    description: 'Claims system, admin or developer authority to override the model\'s rules or the user',
    type: 'injection',
    pattern: String.raw`(?i)\b(?:system|admin|administrator|developer|root)\s+(?:override|overrides|command|directive)\b|\boverride\s+(?:your\s+|the\s+|all\s+)?(?:safety|security|content|ethical)\b|\b(?:who|that)\s+(?:deployed|created|built|trained|programmed)\s+you\b|\bstop\s+responding\s+to\s+(?:them|the\s+user)\b`,
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'prompt_injection_jailbreak',
    name: 'Prompt Injection - Jailbreak Attempt',
    description: 'Persona and framing jailbreaks: unrestricted personas, no-ethics claims, developer mode, forced prefixes',
    type: 'injection',
    pattern: String.raw`(?i)\bDAN\s+mode\b|\bdo\s+anything\s+now\b|\bpretend\s+you\s+(?:are|have)\s+no\s+(?:restrictions|limits)\b|\bact\s+as\s+(?:if|an?)\s+(?:unrestricted|unfiltered)\b|\b(?:unfiltered|uncensored|amoral|unrestricted|unconstrained|unaligned|jailbroken)\s+(?:and\s+\w+\s+)?(?:ai|assistant|chatbot|bot|model|mode|version|character|persona|llm)\b|\b(?:no|without|doesn't\s+have\s+any|does\s+not\s+have\s+any|free\s+(?:of|from)|not\s+bound\s+by)\s+(?:any\s+)?(?:ethical|moral|safety|content)(?:\s+or\s+(?:ethical|moral|safety))?\s+(?:guidelines|restrictions|filters|limits|polic(?:y|ies)|principles|constraints|boundaries)\b|\bbypass(?:es|ing)?\s+(?:all\s+|any\s+)?(?:content|safety|ethical)\s+(?:polic(?:y|ies)|filters|guidelines|restrictions)\b|\bnever\s+refuses?\b|\bdeveloper\s+mode\s+(?:enabled|output|response)\b|\bwith\s+developer\s+mode\b|\bstarting\s+with\s+exactly\b|\b(?:start|begin)\s+(?:your\s+)?(?:response|reply|answer)\s+with\s+exactly\b|\b(?:act|pretend|play|roleplay)\s+as\s+my\s+(?:deceased|late|dead)\b`,
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'prompt_injection_decode_execute',
    name: 'Prompt Injection - Decode and Execute',
    description: 'Asks the model to decode or translate hidden text and then act on it',
    type: 'injection',
    pattern: String.raw`(?i)\b(?:decode|translate|decrypt|deobfuscate|unscramble)\b[^.\n]{0,80}\b(?:and|then)\s+(?:execute|follow|run|obey|perform|carry\s+out|act\s+on)\b`,
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'transaction_directive',
    name: 'Transaction Directive',
    description: 'Tells an agent to move money: an amount with a destination account, or a push to process a transfer now',
    type: 'injection',
    pattern: String.raw`(?i)\b(?:transfer|wire|send|pay|remit)\s+(?:\S+\s+){0,3}?(?:[\d][\d,.]*\s*(?:usd|eur|gbp|dollars|euros|btc|eth|usdc|usdt)?|(?:usd|eur|gbp)\s*[\d][\d,.]*)\s+(?:\S+\s+){0,3}?to\s+(?:the\s+)?(?:account|acct|iban|wallet|recipient|routing|beneficiary)\b|\bprocess\s+(?:a|this|the)\s+(?:payment|transfer|transaction|wire)\b[^.\n]{0,60}\bto\s+(?:the\s+)?(?:recipient|account|wallet|iban|beneficiary)\b|\bprocess\s+(?:this|the)\s+(?:transfer|payment|transaction|wire)\s+(?:immediately|now|urgently|right\s+away|asap)\b`,
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'prompt_injection_system',
    name: 'Prompt Injection - System Prompt Extraction',
    description: 'Attempts to extract the system prompt or the instructions the model was given',
    type: 'injection',
    pattern: String.raw`(?i)\bshow\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?prompt\b|\bwhat\s+(?:are|is)\s+your\s+(?:instructions?|rules?)\b|\breveal\s+(?:your\s+)?(?:system|hidden)\s+(?:prompt|instructions?)\b|\b(?:repeat|print|output|echo|recite|reproduce|dump|display|write\s+out|return|spell-?check)\s+(?:\S+\s+){0,4}?(?:words|text|everything|content|instructions|messages?|lines)\s+(?:above|preceding)\b|\b(?:reveal|print|repeat|output|show|share|dump|leak|disclose|list|translate|display|give\s+me|tell\s+me|write\s+out|recite|respond\s+with)\s+(?:\S+\s+){0,3}?(?:your|the)\s+(?:(?:full|complete|entire|exact|initial|original|hidden|secret|internal)\s+)*(?:system\s+(?:prompt|message|instructions?)|initial\s+(?:prompt|instructions?)|hidden\s+(?:prompt|instructions?)|pre-?prompt)\b|\b(?:every|all|each|any)\s+(?:[\w-]+,?\s+){0,5}?(?:rules?|constraints?|instructions?|guidelines?),?\s+(?:\w+\s+){0,2}?you\s+(?:have\s+been|'ve\s+been|were)\s+(?:given|told|provided)\b|\b(?:print|show|spell-?check|repeat|output|drucke\w*|zeig\w*|imprime\w*)\s+(?:\S+\s+){0,4}?(?:above|obige\w*|previous|vorherige\w*)\s+(?:prompt|prompts|text|instructions|eingabeaufforderung|anweisungen|texte?s?)\b|\b(?:show|zeig\w*|give|list|print|reveal)\s+(?:me\s+|mir\s+)?(?:all\s+|alle\s+)?(?:of\s+)?(?:your|deine|ihre)\s+(?:prompt\s+texts?|prompts|anweisungen|initial\s+instructions)\b`,
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'prompt_injection_data_harvest',
    name: 'Prompt Injection - User Data Harvest',
    description: 'Asks the model to collect or output the user\'s private data',
    type: 'injection',
    pattern: String.raw`(?i)\b(?:respond|reply|include|output|print|list|share|extract|collect|harvest|gather|reveal|send)\s+(?:with\s+)?(?:\S+\s+){0,3}?(?:the\s+)?(?:user's|users'|their)\s+(?:\w+\s+){0,2}?(?:conversation\s+history|chat\s+history|messages|e-?mail\s+addresses|location|credentials|passwords?|session|cookies|account\s+details|contacts)\b`,
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'prompt_injection_roleplay',
    name: 'Prompt Injection - Malicious Roleplay',
    description: 'Roleplay instructions that may bypass safety',
    type: 'injection',
    pattern: String.raw`(?i)\byou\s+are\s+now\s+(?:evil|malicious|unrestricted)\b|\broleplay\s+as\s+(?:a\s+)?(?:hacker|criminal)\b|\bpretend\s+(?:to\s+be|you\s+are)\s+(?:a\s+)?(?:virus|malware)\b`,
    severity: 'medium',
    action: 'alert',
    enabled: true
  },
  {
    id: 'prompt_injection_recon',
    name: 'Prompt Injection - Policy Reconnaissance',
    description: 'Probes for the model\'s permissions or its reasoning trace (common, so low severity)',
    type: 'injection',
    pattern: String.raw`(?i)\bwhat\s+(?:tools|capabilities|urls?|url\s+patterns|domains|commands|actions|files|paths)\b[^?.]{0,60}\b(?:are\s+you|you\s+are)\s+(?:\w+\s+)?(?:allowed|permitted|denied|forbidden|not\s+allowed|blocked)\b|\b(?:output|reveal|print|show|share|dump|expose)\s+(?:me\s+)?your\s+(?:(?:full|raw|hidden|internal|private)\s+)*(?:reasoning\s+trace|chain[\s-]of[\s-]thought|hidden\s+reasoning|internal\s+reasoning)\b|\b(?:stay|remain)\s+in\s+character\b`,
    severity: 'low',
    action: 'log',
    enabled: true
  }
];

// ============================================================================
// Exfiltration Detection Patterns
// ============================================================================

export const EXFILTRATION_PATTERNS: DetectionRule[] = [
  {
    id: 'templated_exfil_url',
    name: 'Templated Exfiltration URL',
    description: 'A URL with a placeholder for session, token, conversation or other private data in its query or hostname, for an agent to fill in and fetch',
    type: 'exfiltration',
    pattern: String.raw`(?i)https?://[^\s"'<>]*[?&][\w.-]*=\{\s*(?!your_)[A-Za-z_]*(?:session|token|email|context|conversation|secret|api_?key|password|history|cookie|credential|user_data)[A-Za-z_]*\s*\}|\{\s*[A-Za-z_]*(?:email|token|secret|session|password|api_?key|context|conversation|cookie|credential)[A-Za-z_]*\s*\}\.[a-z0-9-]+\.[a-z0-9.-]*[a-z]{2,}`,
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'exfiltration_directive',
    name: 'Exfiltration Directive',
    description: 'Text telling an agent to send credentials, session data or other private data to a URL',
    type: 'exfiltration',
    pattern: String.raw`(?i)\b(?:send|forward|post|upload|transmit|exfiltrate|leak|e-?mail|submit|report)\b[^\n]{0,80}?\b(?:credentials?|session(?:\s+(?:info|data|tokens?|cookies?))?|cookies?|tokens?|passwords?|(?:conversation|chat|browsing)\s+history|(?:our|the|this)\s+conversation|location|e-?mail\s+addresses|api\s+keys?|secrets?|personal\s+(?:data|information)|contacts|private\s+keys?)\b[^\n]{0,80}?(?:https?://|\b[\w.+-]+@[\w-]+\.[\w.-]+)|\b(?:send|e-?mail|forward|mail)\b[^\n]{0,30}?\b[\w.+-]+@[\w-]+\.[\w.-]+[^\n]{0,40}?\b(?:conversation|chat\s+history|credentials|session|passwords?|private\s+keys?|api\s+keys?|ssh)\b`,
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'suspicious_url_post',
    name: 'Suspicious Data POST',
    description: 'POST requests to suspicious or unknown domains',
    type: 'exfiltration',
    pattern: '(?i)(fetch|axios|request|http\\.post|requests\\.post|curl\\s+-X\\s+POST).*\\b(ngrok|webhook\\.site|requestbin|pipedream|beeceptor|mockbin|postb\\.in)\\b',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'dns_exfiltration',
    name: 'DNS Exfiltration Pattern',
    description: 'Potential DNS-based data exfiltration',
    type: 'exfiltration',
    pattern: '(?i)(nslookup|dig|host)\\s+[A-Za-z0-9+/=]{20,}\\.',
    severity: 'high',
    action: 'alert',
    enabled: true
  },
  {
    id: 'data_encoding_suspicious',
    name: 'Suspicious Data Encoding',
    description: 'Base64 or hex encoding of potentially sensitive data',
    type: 'exfiltration',
    pattern: '(?i)(btoa|Buffer\\.from|base64\\.b64encode).*\\b(password|secret|key|token|credential)\\b',
    severity: 'medium',
    action: 'alert',
    enabled: true
  }
];

// ============================================================================
// Dangerous URL Patterns
// ============================================================================

export const DANGEROUS_URL_PATTERNS = [
  // Data exfiltration services
  /webhook\.site/i,
  /requestbin\.(com|net)/i,
  /pipedream\.net/i,
  /beeceptor\.com/i,
  /mockbin\.org/i,
  /postb\.in/i,
  /hookbin\.com/i,
  
  // Temporary file sharing
  /file\.io/i,
  /transfer\.sh/i,
  /0x0\.st/i,
  
  // Known malicious TLDs
  /\.(tk|ml|ga|cf|gq)$/i,
  
  // IP addresses (usually suspicious)
  /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
];

// ============================================================================
// All Default Rules Combined
// ============================================================================

export const DEFAULT_RULES: DetectionRule[] = [
  ...SECRET_PATTERNS,
  ...PII_PATTERNS,
  ...CODE_PATTERNS,
  ...INJECTION_PATTERNS,
  ...EXFILTRATION_PATTERNS
];
