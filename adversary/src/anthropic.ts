/**
 * Minimal Anthropic Messages API client.
 *
 * Uses fetch() directly — no SDK dependency, no extra weight in the
 * published package. Only invoked when DemoTarget is in real mode and
 * ANTHROPIC_API_KEY is set.
 *
 * Pricing reference (as of Oct 2026, first-party API, $/MTok in/out):
 *   claude-haiku-5-5  — $0.10 / $0.50 (prompts up to 100K tokens)
 *   claude-sonnet-5-5 — $2.00 / $10.00
 *   claude-opus-5-5   — $4.00 / $20.00
 *
 * Claude 3.5 Haiku/Sonnet and 3.7 Sonnet were retired in 2025-26 and
 * now return errors; Opus 4.1 retired 2026-08-05.
 *
 * For a full 68-attack demo run with Haiku 5.5, expect well under $0.01.
 */

const ANTHROPIC_API_URL = 'https://api.anthropic.com/v1/messages';
const API_VERSION = '2023-06-01';

/** Per-million-token pricing for cost estimation */
export const MODEL_PRICING: Record<string, { input: number; output: number }> = {
  'claude-haiku-5-5':  { input: 0.10, output: 0.50 },
  'claude-haiku-4-5':  { input: 1.00, output: 5.00 },
  'claude-sonnet-5-5': { input: 2.00, output: 10.00 },
  'claude-sonnet-5':   { input: 2.00, output: 10.00 },
  'claude-sonnet-4-6': { input: 3.00, output: 15.00 },
  'claude-opus-5-5':   { input: 4.00, output: 20.00 },
  'claude-opus-5':     { input: 5.00, output: 25.00 },
  'claude-opus-4-8':   { input: 5.00, output: 25.00 },
  'claude-opus-4-7':   { input: 5.00, output: 25.00 },
};

export const DEFAULT_MODEL = 'claude-haiku-5-5';

/**
 * Claude 5-generation models think by default. These calls use small
 * max_tokens budgets and want a direct answer, so ask for low effort
 * to keep thinking from consuming the whole budget. Older models
 * (e.g. Haiku 4.5) reject the effort parameter, so only send it here.
 */
function defaultEffort(model: string): string | undefined {
  return /^claude-(haiku|sonnet|opus|fable)-5/.test(model) ? 'low' : undefined;
}

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
  /** output_config.effort; defaults to "low" on 5-generation models */
  effort?: string;
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
  const effort = opts.effort ?? defaultEffort(model);

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
        ...(effort ? { output_config: { effort } } : {}),
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
