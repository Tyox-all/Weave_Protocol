/**
 * LLM pricing table — per-million-token cost for the major providers.
 *
 * Prices are current as of Jun 2026. Sources are provider public pricing
 * pages. Update quarterly.
 *
 * For providers not in this table (custom endpoints, self-hosted local
 * models), cost is 0 — the tracker will only enforce token/call caps,
 * not USD caps.
 *
 * Users can override or extend the table via `registerPricing()`.
 */

export interface Price {
  /** USD per 1,000,000 input tokens */
  input: number;
  /** USD per 1,000,000 output tokens */
  output: number;
}

/**
 * Pricing table, keyed by "provider:model".
 * Provider names normalized to lowercase.
 */
export const LLM_PRICING: Record<string, Price> = {
  // ─── Anthropic ─────────────────────────────────────────────
  'anthropic:claude-3-5-haiku-20241022':  { input: 1.00, output: 5.00 },
  'anthropic:claude-3-5-sonnet-20241022': { input: 3.00, output: 15.00 },
  'anthropic:claude-3-7-sonnet-latest':   { input: 3.00, output: 15.00 },
  'anthropic:claude-3-7-sonnet-20250219': { input: 3.00, output: 15.00 },
  'anthropic:claude-3-5-sonnet-latest':   { input: 3.00, output: 15.00 },
  'anthropic:claude-opus-4-1':            { input: 15.00, output: 75.00 },
  'anthropic:claude-opus-4-7':            { input: 15.00, output: 75.00 },
  'anthropic:claude-sonnet-4-5':          { input: 3.00, output: 15.00 },
  'anthropic:claude-haiku-4-5-20251001':  { input: 1.00, output: 5.00 },

  // ─── OpenAI ────────────────────────────────────────────────
  'openai:gpt-4o':                        { input: 2.50, output: 10.00 },
  'openai:gpt-4o-2024-11-20':             { input: 2.50, output: 10.00 },
  'openai:gpt-4o-mini':                   { input: 0.15, output: 0.60 },
  'openai:gpt-4o-mini-2024-07-18':        { input: 0.15, output: 0.60 },
  'openai:gpt-4-turbo':                   { input: 10.00, output: 30.00 },
  'openai:gpt-4':                         { input: 30.00, output: 60.00 },
  'openai:gpt-3.5-turbo':                 { input: 0.50, output: 1.50 },
  'openai:o1':                            { input: 15.00, output: 60.00 },
  'openai:o1-preview':                    { input: 15.00, output: 60.00 },
  'openai:o1-mini':                       { input: 3.00, output: 12.00 },
  'openai:o3':                            { input: 15.00, output: 60.00 },
  'openai:o3-mini':                       { input: 1.10, output: 4.40 },

  // ─── Google ────────────────────────────────────────────────
  'google:gemini-1.5-flash':              { input: 0.075, output: 0.30 },
  'google:gemini-1.5-flash-8b':           { input: 0.0375, output: 0.15 },
  'google:gemini-1.5-pro':                { input: 1.25, output: 5.00 },
  'google:gemini-2.0-flash':              { input: 0.10, output: 0.40 },
  'google:gemini-2.0-flash-exp':          { input: 0.10, output: 0.40 },
  'google:gemini-2.5-flash':              { input: 0.15, output: 0.60 },
  'google:gemini-2.5-pro':                { input: 1.25, output: 10.00 },

  // ─── Local / self-hosted (free) ────────────────────────────
  'local:llama':                          { input: 0, output: 0 },
  'local:llama3':                         { input: 0, output: 0 },
  'local:mistral':                        { input: 0, output: 0 },
  'local:qwen':                           { input: 0, output: 0 },
  'ollama:llama3':                        { input: 0, output: 0 },
  'ollama:mistral':                       { input: 0, output: 0 },
  'ollama:qwen':                          { input: 0, output: 0 },
  'lmstudio:local':                       { input: 0, output: 0 },
};

/**
 * Look up pricing for a provider+model combination.
 * Returns null if unknown (caller decides how to handle — usually treated as 0).
 */
export function lookupPricing(provider: string, model: string): Price | null {
  const key = `${provider.toLowerCase()}:${model}`;
  if (LLM_PRICING[key]) return LLM_PRICING[key];

  // Try provider-prefix match (e.g. "anthropic:claude-*" for a version we
  // don't know exactly). Best-effort fallback.
  const providerPrefix = provider.toLowerCase() + ':';
  for (const k of Object.keys(LLM_PRICING)) {
    if (k.startsWith(providerPrefix)) {
      const familyStem = k.slice(providerPrefix.length).split('-').slice(0, 3).join('-');
      if (model.toLowerCase().includes(familyStem)) return LLM_PRICING[k];
    }
  }
  return null;
}

/**
 * Register or override pricing for a provider:model pair.
 * Use for custom endpoints, forks, or when a new model ships between updates.
 */
export function registerPricing(provider: string, model: string, price: Price): void {
  LLM_PRICING[`${provider.toLowerCase()}:${model}`] = price;
}

/**
 * Calculate USD cost given provider, model, and token counts.
 * Returns 0 for unknown provider:model combinations.
 */
export function estimateLLMCost(provider: string, model: string, inputTokens: number, outputTokens: number): number {
  const p = lookupPricing(provider, model);
  if (!p) return 0;
  return (inputTokens / 1_000_000) * p.input + (outputTokens / 1_000_000) * p.output;
}
