import { describe, expect, it } from 'vitest';
import { DEFAULT_RULES } from '../../src/constants.js';

/**
 * These rules use the PCRE-style inline `(?i)` flag, which JavaScript's
 * RegExp rejects. Every analyzer catches the SyntaxError and skips the rule,
 * so none of them ever fire. Pinned here so new breakage fails the build and
 * fixes force this list to shrink.
 */
const KNOWN_INVALID_RULES = [
  'aws_secret_access_key',
  'google_oauth_client_secret',
  'gemini_api_key',
  'gcp_project_credentials',
  'basic_auth_header',
  'bearer_token',
  'database_url',
  'generic_api_key',
  'generic_password',
  'npm_token',
  'docker_auth',
  'azure_storage_key',
  'shell_injection',
  'sql_injection_pattern',
  'base64_decode_exec',
  'disable_ssl_verify',
  'prompt_injection_ignore',
  'prompt_injection_jailbreak',
  'prompt_injection_system',
  'prompt_injection_roleplay',
  'suspicious_url_post',
  'dns_exfiltration',
  'data_encoding_suspicious',
];

describe('DEFAULT_RULES', () => {
  it('has unique rule ids', () => {
    const ids = DEFAULT_RULES.map(r => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('only contains the known set of regexes that JavaScript cannot compile', () => {
    const invalid = DEFAULT_RULES.filter(r => {
      if (!r.pattern) return false;
      try {
        new RegExp(r.pattern, 'g');
        return false;
      } catch {
        return true;
      }
    }).map(r => r.id);
    expect(invalid).toEqual(KNOWN_INVALID_RULES);
  });
});
