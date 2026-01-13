/**
 * Mund - The Guardian Protocol
 * Constants and default configurations
 */

import { Severity, ActionType, DetectorType } from './types.js';
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
    type: DetectorType.SECRET,
    pattern: '(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'aws_secret_access_key',
    name: 'AWS Secret Access Key',
    description: 'Amazon Web Services secret access key',
    type: DetectorType.SECRET,
    pattern: '(?i)aws[_\\-\\s]*secret[_\\-\\s]*access[_\\-\\s]*key[\\s]*[=:]+[\\s]*["\']?[A-Za-z0-9/+=]{40}["\']?',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'github_token',
    name: 'GitHub Token',
    description: 'GitHub personal access token or OAuth token',
    type: DetectorType.SECRET,
    pattern: 'gh[pousr]_[A-Za-z0-9_]{36,}',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'github_fine_grained_token',
    name: 'GitHub Fine-Grained Token',
    description: 'GitHub fine-grained personal access token',
    type: DetectorType.SECRET,
    pattern: 'github_pat_[A-Za-z0-9_]{22,}',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'openai_api_key',
    name: 'OpenAI API Key',
    description: 'OpenAI API key',
    type: DetectorType.SECRET,
    pattern: 'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'openai_api_key_v2',
    name: 'OpenAI API Key (New Format)',
    description: 'OpenAI API key in newer format',
    type: DetectorType.SECRET,
    pattern: 'sk-proj-[A-Za-z0-9_-]{48,}',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'anthropic_api_key',
    name: 'Anthropic API Key',
    description: 'Anthropic Claude API key',
    type: DetectorType.SECRET,
    pattern: 'sk-ant-[A-Za-z0-9_-]{90,}',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'google_api_key',
    name: 'Google API Key',
    description: 'Google Cloud API key',
    type: DetectorType.SECRET,
    pattern: 'AIza[0-9A-Za-z_-]{35}',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'google_oauth_client_secret',
    name: 'Google OAuth Client Secret',
    description: 'Google OAuth 2.0 client secret',
    type: DetectorType.SECRET,
    pattern: '(?i)client[_-]?secret[\\s]*[=:]+[\\s]*["\']?GOCSPX-[A-Za-z0-9_-]{28}["\']?',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'gemini_api_key',
    name: 'Gemini API Key',
    description: 'Google Gemini API key for AI services',
    type: DetectorType.SECRET,
    pattern: '(?i)(GEMINI_API_KEY|GOOGLE_API_KEY)[\\s]*[=:]+[\\s]*["\']?AIza[0-9A-Za-z_-]{35}["\']?',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'google_cloud_service_account',
    name: 'Google Cloud Service Account Key',
    description: 'Google Cloud service account JSON key file content',
    type: DetectorType.SECRET,
    pattern: '"type"\\s*:\\s*"service_account"[\\s\\S]*"private_key"\\s*:\\s*"-----BEGIN',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'google_oauth_refresh_token',
    name: 'Google OAuth Refresh Token',
    description: 'Google OAuth refresh token',
    type: DetectorType.SECRET,
    pattern: '1//[0-9A-Za-z_-]{40,}',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'firebase_api_key',
    name: 'Firebase API Key',
    description: 'Firebase/Google Cloud API key',
    type: DetectorType.SECRET,
    pattern: 'AIza[0-9A-Za-z_-]{35}',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'gcp_project_credentials',
    name: 'GCP Application Credentials Path',
    description: 'Google Application Default Credentials file path',
    type: DetectorType.SECRET,
    pattern: '(?i)GOOGLE_APPLICATION_CREDENTIALS[\\s]*[=:]+[\\s]*["\']?[^"\'\\s]+\\.json["\']?',
    severity: Severity.MEDIUM,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'slack_token',
    name: 'Slack Token',
    description: 'Slack bot, user, or workspace token',
    type: DetectorType.SECRET,
    pattern: 'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'slack_webhook',
    name: 'Slack Webhook URL',
    description: 'Slack incoming webhook URL',
    type: DetectorType.SECRET,
    pattern: 'https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'stripe_api_key',
    name: 'Stripe API Key',
    description: 'Stripe publishable or secret API key',
    type: DetectorType.SECRET,
    pattern: '[sr]k_(live|test)_[A-Za-z0-9]{24,}',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'private_key_block',
    name: 'Private Key',
    description: 'RSA, EC, DSA, or OpenSSH private key',
    type: DetectorType.SECRET,
    pattern: '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'jwt_token',
    name: 'JWT Token',
    description: 'JSON Web Token',
    type: DetectorType.SECRET,
    pattern: 'eyJ[A-Za-z0-9_-]*\\.eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'basic_auth_header',
    name: 'Basic Auth Header',
    description: 'HTTP Basic Authentication header',
    type: DetectorType.SECRET,
    pattern: '(?i)authorization[\\s]*:[\\s]*basic[\\s]+[A-Za-z0-9+/=]{20,}',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'bearer_token',
    name: 'Bearer Token',
    description: 'HTTP Bearer authentication token',
    type: DetectorType.SECRET,
    pattern: '(?i)authorization[\\s]*:[\\s]*bearer[\\s]+[A-Za-z0-9_.-]{20,}',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'database_url',
    name: 'Database Connection URL',
    description: 'Database connection string with credentials',
    type: DetectorType.SECRET,
    pattern: '(?i)(postgres|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@[^/]+',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'generic_api_key',
    name: 'Generic API Key',
    description: 'Generic API key pattern',
    type: DetectorType.SECRET,
    pattern: '(?i)(api[_-]?key|apikey|api[_-]?secret)[\\s]*[=:]+[\\s]*["\']?[A-Za-z0-9_-]{20,}["\']?',
    severity: Severity.MEDIUM,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'generic_password',
    name: 'Generic Password',
    description: 'Password assignment in code or config',
    type: DetectorType.SECRET,
    pattern: '(?i)(password|passwd|pwd)[\\s]*[=:]+[\\s]*["\'][^"\']{8,}["\']',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'npm_token',
    name: 'NPM Token',
    description: 'NPM authentication token',
    type: DetectorType.SECRET,
    pattern: '(?i)//registry\\.npmjs\\.org/:_authToken=[A-Za-z0-9_-]+',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'pypi_token',
    name: 'PyPI Token',
    description: 'Python Package Index API token',
    type: DetectorType.SECRET,
    pattern: 'pypi-[A-Za-z0-9_-]{50,}',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'docker_auth',
    name: 'Docker Auth Config',
    description: 'Docker registry authentication',
    type: DetectorType.SECRET,
    pattern: '(?i)"auth"[\\s]*:[\\s]*"[A-Za-z0-9+/=]{20,}"',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'azure_storage_key',
    name: 'Azure Storage Account Key',
    description: 'Microsoft Azure storage account key',
    type: DetectorType.SECRET,
    pattern: '(?i)AccountKey=[A-Za-z0-9+/=]{88}',
    severity: Severity.CRITICAL,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'sendgrid_api_key',
    name: 'SendGrid API Key',
    description: 'SendGrid email API key',
    type: DetectorType.SECRET,
    pattern: 'SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'twilio_api_key',
    name: 'Twilio API Key',
    description: 'Twilio API key or auth token',
    type: DetectorType.SECRET,
    pattern: 'SK[a-f0-9]{32}',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'mailchimp_api_key',
    name: 'Mailchimp API Key',
    description: 'Mailchimp API key',
    type: DetectorType.SECRET,
    pattern: '[a-f0-9]{32}-us[0-9]{1,2}',
    severity: Severity.MEDIUM,
    action: ActionType.ALERT,
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
    type: DetectorType.PII,
    pattern: '(?<!\\d)\\d{3}-\\d{2}-\\d{4}(?!\\d)',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'credit_card',
    name: 'Credit Card Number',
    description: 'Credit card number (major providers)',
    type: DetectorType.PII,
    pattern: '(?<!\\d)(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})(?!\\d)',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'email_address',
    name: 'Email Address',
    description: 'Email address pattern',
    type: DetectorType.PII,
    pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}',
    severity: Severity.LOW,
    action: ActionType.LOG,
    enabled: true
  },
  {
    id: 'phone_number_us',
    name: 'US Phone Number',
    description: 'US phone number in various formats',
    type: DetectorType.PII,
    pattern: '(?<!\\d)(\\+?1[-.]?)?\\(?[0-9]{3}\\)?[-.]?[0-9]{3}[-.]?[0-9]{4}(?!\\d)',
    severity: Severity.LOW,
    action: ActionType.LOG,
    enabled: true
  },
  {
    id: 'ip_address',
    name: 'IP Address',
    description: 'IPv4 address',
    type: DetectorType.PII,
    pattern: '(?<!\\d)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?!\\d)',
    severity: Severity.INFO,
    action: ActionType.LOG,
    enabled: false
  }
];

// ============================================================================
// Code Pattern Detection (Dangerous Operations)
// ============================================================================

export const CODE_PATTERNS: DetectionRule[] = [
  {
    id: 'shell_injection',
    name: 'Potential Shell Injection',
    description: 'Code that may be vulnerable to shell injection',
    type: DetectorType.CODE_PATTERN,
    pattern: '(?i)(child_process\\.exec|os\\.system|subprocess\\.call|eval\\(|exec\\().*\\$|.*\\{.*\\}',
    severity: Severity.MEDIUM,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'sql_injection_pattern',
    name: 'Potential SQL Injection',
    description: 'String concatenation in SQL queries',
    type: DetectorType.CODE_PATTERN,
    pattern: '(?i)(SELECT|INSERT|UPDATE|DELETE|DROP).*\\+.*\\$|f".*SELECT.*\\{|f".*INSERT.*\\{',
    severity: Severity.MEDIUM,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'dangerous_chmod',
    name: 'Dangerous chmod',
    description: 'chmod with overly permissive permissions',
    type: DetectorType.CODE_PATTERN,
    pattern: 'chmod\\s+([0-7]*7[0-7]{2}|777|\\+x)',
    severity: Severity.MEDIUM,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'rm_rf',
    name: 'Recursive Force Delete',
    description: 'Potentially dangerous rm -rf command',
    type: DetectorType.CODE_PATTERN,
    pattern: 'rm\\s+-[rf]{1,2}\\s+(/|\\$|~|\\.\\.|\\*)',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'curl_bash',
    name: 'Curl to Bash',
    description: 'Piping curl output to bash (dangerous)',
    type: DetectorType.CODE_PATTERN,
    pattern: 'curl\\s+.*\\|\\s*(ba)?sh',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'base64_decode_exec',
    name: 'Base64 Decode Execute',
    description: 'Decoding and executing base64 content',
    type: DetectorType.CODE_PATTERN,
    pattern: '(?i)(base64\\s+-d|atob|Buffer\\.from.*base64).*\\|.*(sh|eval|exec)',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'disable_ssl_verify',
    name: 'SSL Verification Disabled',
    description: 'Code that disables SSL certificate verification',
    type: DetectorType.CODE_PATTERN,
    pattern: '(?i)(verify\\s*=\\s*False|rejectUnauthorized\\s*:\\s*false|CURLOPT_SSL_VERIFYPEER\\s*,\\s*0|InsecureSkipVerify\\s*:\\s*true)',
    severity: Severity.MEDIUM,
    action: ActionType.ALERT,
    enabled: true
  }
];

// ============================================================================
// Injection Detection Patterns
// ============================================================================

export const INJECTION_PATTERNS: DetectionRule[] = [
  {
    id: 'prompt_injection_ignore',
    name: 'Prompt Injection - Ignore Instructions',
    description: 'Attempts to make AI ignore previous instructions',
    type: DetectorType.INJECTION,
    pattern: '(?i)(ignore\\s+(all\\s+)?(previous|prior|above)\\s+(instructions?|prompts?|context)|disregard\\s+(everything|all)\\s+(above|before))',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'prompt_injection_jailbreak',
    name: 'Prompt Injection - Jailbreak Attempt',
    description: 'Common jailbreak patterns',
    type: DetectorType.INJECTION,
    pattern: '(?i)(DAN\\s+mode|do\\s+anything\\s+now|pretend\\s+you\\s+(are|have)\\s+no\\s+(restrictions|limits)|act\\s+as\\s+(if|an?)\\s+(unrestricted|unfiltered))',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'prompt_injection_system',
    name: 'Prompt Injection - System Prompt Extraction',
    description: 'Attempts to extract system prompts',
    type: DetectorType.INJECTION,
    pattern: '(?i)(show\\s+(me\\s+)?(your|the)\\s+(system\\s+)?prompt|what\\s+(are|is)\\s+your\\s+(instructions?|rules?)|reveal\\s+(your\\s+)?(system|hidden)\\s+(prompt|instructions?))',
    severity: Severity.MEDIUM,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'prompt_injection_roleplay',
    name: 'Prompt Injection - Malicious Roleplay',
    description: 'Roleplay instructions that may bypass safety',
    type: DetectorType.INJECTION,
    pattern: '(?i)(you\\s+are\\s+now\\s+(evil|malicious|unrestricted)|roleplay\\s+as\\s+(a\\s+)?(hacker|criminal)|pretend\\s+(to\\s+be|you\\s+are)\\s+(a\\s+)?(virus|malware))',
    severity: Severity.MEDIUM,
    action: ActionType.ALERT,
    enabled: true
  }
];

// ============================================================================
// Exfiltration Detection Patterns
// ============================================================================

export const EXFILTRATION_PATTERNS: DetectionRule[] = [
  {
    id: 'suspicious_url_post',
    name: 'Suspicious Data POST',
    description: 'POST requests to suspicious or unknown domains',
    type: DetectorType.EXFILTRATION,
    pattern: '(?i)(fetch|axios|request|http\\.post|requests\\.post|curl\\s+-X\\s+POST).*\\b(ngrok|webhook\\.site|requestbin|pipedream|beeceptor|mockbin|postb\\.in)\\b',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'dns_exfiltration',
    name: 'DNS Exfiltration Pattern',
    description: 'Potential DNS-based data exfiltration',
    type: DetectorType.EXFILTRATION,
    pattern: '(?i)(nslookup|dig|host)\\s+[A-Za-z0-9+/=]{20,}\\.',
    severity: Severity.HIGH,
    action: ActionType.ALERT,
    enabled: true
  },
  {
    id: 'data_encoding_suspicious',
    name: 'Suspicious Data Encoding',
    description: 'Base64 or hex encoding of potentially sensitive data',
    type: DetectorType.EXFILTRATION,
    pattern: '(?i)(btoa|Buffer\\.from|base64\\.b64encode).*\\b(password|secret|key|token|credential)\\b',
    severity: Severity.MEDIUM,
    action: ActionType.ALERT,
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
