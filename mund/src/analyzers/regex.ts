/**
 * Mund - The Guardian Protocol
 * Rule pattern compilation
 *
 * Rule patterns are often written in PCRE/RE2 style with a leading inline
 * flag group like `(?i)`. JavaScript's RegExp rejects that syntax, so
 * translate leading inline flags into RegExp flags instead.
 */

const INLINE_FLAGS = /^\(\?([imsu]+)\)/;

export function compileRulePattern(pattern: string, flags = ''): RegExp {
  const m = INLINE_FLAGS.exec(pattern);
  if (!m) return new RegExp(pattern, flags);
  const merged = new Set([...flags, ...m[1]]);
  return new RegExp(pattern.slice(m[0].length), [...merged].join(''));
}
