/**
 * ⚠️ EXPERIMENTAL — NOT AUDITED ⚠️
 *
 * @weave_protocol/yoxallismus is a beta post-quantum cryptographic
 * composition layer. It has NOT undergone external cryptographic audit.
 *
 * DO NOT USE for:
 *   - Regulated data (HIPAA, PCI-DSS, SOC2-audited storage)
 *   - Medical records
 *   - Financial records
 *   - Legal evidence
 *   - Anything where a cryptographic failure causes real-world harm
 *
 * DO USE for:
 *   - Research on post-quantum agent architectures
 *   - Experimentation with PQ-hybrid primitives
 *   - Development against future PQ-cryptographic patterns
 *   - Learning post-quantum cryptography by example
 *
 * See THREAT_MODEL.md for the full list of what this library defends
 * against, what it doesn't, and what its known limitations are.
 *
 * See SECURITY.md for the bug bounty program.
 */

const BANNER = [
  '',
  '  ⚠️  \x1b[41m\x1b[1;37m EXPERIMENTAL — NOT AUDITED \x1b[0m',
  '',
  '  @weave_protocol/yoxallismus is a beta post-quantum cryptographic',
  '  composition layer. It has not undergone external cryptographic audit.',
  '',
  '  Do NOT use for regulated, medical, financial, or legal data.',
  '',
  '  See THREAT_MODEL.md and SECURITY.md before adopting.',
  '  Silence this banner with: YOXALL_SILENCE_BETA_WARNING=1',
  '',
];

let bannerShown = false;

/**
 * Print the beta warning banner to stderr on first import.
 * Silenceable via env var. Called once per Node process.
 */
export function showBetaBanner(): void {
  if (bannerShown) return;
  bannerShown = true;
  if (process.env.YOXALL_SILENCE_BETA_WARNING === '1') return;
  for (const line of BANNER) process.stderr.write(line + '\n');
}

/**
 * Machine-readable metadata about the library's status.
 * Consumed by CLI, by import-time banner, and by test harness.
 */
export const STATUS = {
  version: '0.1.0-beta.0',
  audited: false,
  auditPlanned: false,
  status: 'experimental',
  productionReady: false,
  scopeForUse: [
    'research',
    'experimentation',
    'development',
    'learning post-quantum patterns',
  ],
  scopeForNonUse: [
    'regulated data (HIPAA, PCI-DSS, SOC2)',
    'medical records',
    'financial records',
    'legal evidence',
    'production security-critical systems',
  ],
  primitivesUsed: {
    kem: ['X25519 (classical)', 'ML-KEM-768 (post-quantum, NIST FIPS 203)'],
    aead: ['AES-256-GCM (Node crypto)'],
    kdf: ['HKDF-SHA-256 (Node crypto)'],
    ratchet: ['symmetric ratchet only in v0.1; DH double-ratchet planned v0.2'],
  },
  knownLimitations: [
    'no threshold encryption yet',
    'no zero-knowledge proofs yet',
    'no verifiable delay functions yet',
    'no cascade cipher yet',
    'no FHE integration yet',
    'no Yoxallismus v1 backward-compat shim yet',
    'no formal audit performed',
    'no quantum RNG integration yet',
  ],
} as const;
