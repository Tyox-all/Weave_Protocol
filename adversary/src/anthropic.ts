/**
 * Minimal Anthropic Messages API client.
 *
 * Uses fetch() directly — no SDK dependency, no extra weight in the
 * published package. Only invoked when DemoTarget is in real mode and
 * ANTHROPIC_API_KEY is set.
 *
 * Pricing reference (as of Jun 2026):
 *   claude-3-5-haiku-20241022 — $1.00 / MTok input, $5.00 / MTok output
 *   claude-3-5-sonnet-20241022 — $3.00 / MTok input, $15.00 / MTok output
 *
 * For a full 68-attack demo run with Haiku, expect ~$0.02-0.05.
 */

const ANTHROPIC_API_URL = 'https://api.anthropic.com/v1/messages';
const API_VERSION = '2023-06-01';

/** Per-million-token pricing for cost estimation */
export const MODEL_PRICING: Record<string, { input: number; output: number }> = {
  'claude-3-5-haiku-20241022':  { input: 1.00, output: 5.00 },
  'claude-3-5-sonnet-20241022': { input: 3.00, output: 15.00 },
  'claude-3-7-sonnet-latest':   { input: 3.00, output: 15.00 },
  'claude-opus-4-1':            { input: 15.00, output: 75.00 },
  'claude-opus-4-7':            { input: 15.00, output: 75.00 },
};

export const DEFAULT_MODEL = 'claude-3-5-haiku-20241022';

export interface ApiResponse {
  text: string;
  inputTokens: number;
  outputTokens: number;
  model: string;
  stopReason: string;
}

export interface ApiCallOptions {
  apiKey: string;
  model?: string;
  systemPrompt: string;
  userMessage: string;
  maxTokens?: number;
  timeoutMs?: number;
}

/**
 * Make a single Messages API call. Returns parsed text + usage.
 *
 * Throws if the API rejects the request — caller is expected to
 * handle this (e.g. classify the attack as "errored / blocked").
 */
export async function callAnthropic(opts: ApiCallOptions): Promise<ApiResponse> {
  const model = opts.model || DEFAULT_MODEL;
  const maxTokens = opts.maxTokens ?? 1024;
  const timeoutMs = opts.timeoutMs ?? 30_000;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res: Response;
  try {
    res = await fetch(ANTHROPIC_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': opts.apiKey,
        'anthropic-version': API_VERSION,
      },
      body: JSON.stringify({
        model,
        max_tokens: maxTokens,
        system: opts.systemPrompt,
        messages: [{ role: 'user', content: opts.userMessage }],
      }),
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    const errBody = await res.text().catch(() => '<no body>');
    throw new Error(`Anthropic API ${res.status}: ${errBody.slice(0, 500)}`);
  }

  const data: any = await res.json();

  // Extract text from content blocks (Anthropic responses can have multiple blocks)
  const text = Array.isArray(data.content)
    ? data.content
        .filter((b: any) => b.type === 'text')
        .map((b: any) => b.text)
        .join('\n')
    : '';

  return {
    text,
    inputTokens: data.usage?.input_tokens ?? 0,
    outputTokens: data.usage?.output_tokens ?? 0,
    model: data.model || model,
    stopReason: data.stop_reason || 'unknown',
  };
}

/**
 * Calculate USD cost from token usage.
 * Returns 0 if model pricing is unknown.
 */
export function estimateCost(model: string, inputTokens: number, outputTokens: number): number {
  const pricing = MODEL_PRICING[model];
  if (!pricing) return 0;
  return (inputTokens / 1_000_000) * pricing.input + (outputTokens / 1_000_000) * pricing.output;
}
