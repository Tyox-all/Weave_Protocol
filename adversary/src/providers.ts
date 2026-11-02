/**
 * Provider-agnostic model calls.
 *
 * Claude goes through the native Messages API (./anthropic.ts). Every
 * other provider here speaks the OpenAI Chat Completions protocol, so
 * one client covers hosted models (Gemini, DeepSeek, Kimi, Qwen, GLM,
 * OpenRouter, ...) and local ones (Ollama, LM Studio, vLLM).
 *
 * Model names change faster than this file, so only Claude has a
 * default model; every other provider needs an explicit model id.
 */

import { callAnthropic, DEFAULT_MODEL, estimateCost as estimateAnthropicCost, MODEL_PRICING } from './anthropic.js';

export type Protocol = 'anthropic' | 'openai';

export interface ProviderPreset {
  /** Human-readable name for banners and reports */
  label: string;
  protocol: Protocol;
  baseUrl: string;
  /** Env vars checked for the API key, in order. Empty = no key needed. */
  keyEnv: string[];
  /** Model used when none is given (Claude only) */
  defaultModel?: string;
  /** reasoning_effort sent by default, for thinking models whose reasoning
   *  would otherwise use up the small max_tokens budgets used here */
  defaultReasoningEffort?: string;
  /** Local models cost nothing per token */
  free?: boolean;
}

export const PROVIDERS: Record<string, ProviderPreset> = {
  anthropic:  { label: 'Anthropic',              protocol: 'anthropic', baseUrl: 'https://api.anthropic.com/v1', keyEnv: ['ANTHROPIC_API_KEY'], defaultModel: DEFAULT_MODEL },
  openai:     { label: 'OpenAI',                 protocol: 'openai', baseUrl: 'https://api.openai.com/v1', keyEnv: ['OPENAI_API_KEY'] },
  gemini:     { label: 'Google Gemini',          protocol: 'openai', baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai', keyEnv: ['GEMINI_API_KEY', 'GOOGLE_API_KEY'], defaultReasoningEffort: 'low' },
  deepseek:   { label: 'DeepSeek',               protocol: 'openai', baseUrl: 'https://api.deepseek.com/v1', keyEnv: ['DEEPSEEK_API_KEY'] },
  moonshot:   { label: 'Moonshot (Kimi)',        protocol: 'openai', baseUrl: 'https://api.moonshot.ai/v1', keyEnv: ['MOONSHOT_API_KEY'] },
  qwen:       { label: 'Alibaba Model Studio (Qwen)', protocol: 'openai', baseUrl: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1', keyEnv: ['DASHSCOPE_API_KEY'] },
  zai:        { label: 'Z.ai (GLM)',             protocol: 'openai', baseUrl: 'https://api.z.ai/api/paas/v4', keyEnv: ['ZAI_API_KEY', 'ZHIPU_API_KEY'] },
  openrouter: { label: 'OpenRouter',             protocol: 'openai', baseUrl: 'https://openrouter.ai/api/v1', keyEnv: ['OPENROUTER_API_KEY'] },
  groq:       { label: 'Groq',                   protocol: 'openai', baseUrl: 'https://api.groq.com/openai/v1', keyEnv: ['GROQ_API_KEY'] },
  together:   { label: 'Together AI',            protocol: 'openai', baseUrl: 'https://api.together.xyz/v1', keyEnv: ['TOGETHER_API_KEY'] },
  ollama:     { label: 'Ollama (local)',         protocol: 'openai', baseUrl: 'http://localhost:11434/v1', keyEnv: [], free: true },
  lmstudio:   { label: 'LM Studio (local)',      protocol: 'openai', baseUrl: 'http://localhost:1234/v1', keyEnv: [], free: true },
};

export const DEFAULT_PROVIDER = 'anthropic';

export interface ModelConfig {
  provider: string;
  model: string;
  baseUrl: string;
  /** Undefined for providers that need no key */
  apiKey?: string;
  /** Name of the env var the key came from, for error messages */
  keySource?: string;
  reasoningEffort?: string;
  /** Requests per minute to stay under; calls are spaced to fit (free tiers) */
  rpm?: number;
}

export interface ResolveOptions {
  provider?: string;
  model?: string;
  /** Overrides the preset base URL (self-hosted vLLM, a proxy, a regional endpoint) */
  baseUrl?: string;
  apiKey?: string;
  reasoningEffort?: string;
  rpm?: number;
  env?: Record<string, string | undefined>;
}

/**
 * Turn provider/model/key options into a complete call config.
 * Throws with an actionable message when something is missing.
 */
export function resolveModelConfig(opts: ResolveOptions = {}): ModelConfig {
  const env = opts.env ?? process.env;
  const provider = (opts.provider || DEFAULT_PROVIDER).toLowerCase();
  const preset = PROVIDERS[provider];
  if (!preset) {
    throw new Error(`Unknown provider "${provider}". Known: ${Object.keys(PROVIDERS).join(', ')}`);
  }
  const model = opts.model || preset.defaultModel;
  if (!model) {
    throw new Error(`Provider "${provider}" needs a model id (--model=<id>); model names change too often to default.`);
  }
  let apiKey = opts.apiKey;
  let keySource: string | undefined = apiKey ? 'argument' : undefined;
  for (const name of preset.keyEnv) {
    if (apiKey) break;
    if (env[name]) { apiKey = env[name]; keySource = name; }
  }
  if (!apiKey && preset.keyEnv.length > 0) {
    throw new Error(`Provider "${provider}" needs an API key: set ${preset.keyEnv.join(' or ')}.`);
  }
  return {
    provider,
    model,
    baseUrl: (opts.baseUrl || preset.baseUrl).replace(/\/+$/, ''),
    apiKey,
    keySource,
    reasoningEffort: opts.reasoningEffort ?? preset.defaultReasoningEffort,
    ...(opts.rpm && opts.rpm > 0 ? { rpm: opts.rpm } : {}),
  };
}

export interface ModelResponse {
  text: string;
  inputTokens: number;
  outputTokens: number;
  model: string;
  stopReason: string;
}

export interface ModelCallOptions {
  systemPrompt: string;
  userMessage: string;
  maxTokens?: number;
  timeoutMs?: number;
}

/** Rate limits and overload are worth retrying; other errors are not. */
const RETRYABLE = /API (408|429|500|502|503|504|529)\b/;

/**
 * A daily quota, or a provider asking for a wait longer than a minute,
 * won't clear within a run; retrying only stalls it. Gemini's free tier
 * says "requests per day" and "retry in 11h36m53s".
 */
export function isLongWait(message: string): boolean {
  if (/per ?day/i.test(message)) return true;
  const m = /retry (?:in|after) (?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?/i.exec(message);
  if (!m || !(m[1] || m[2] || m[3])) return false;
  const seconds = Number(m[1] ?? 0) * 3600 + Number(m[2] ?? 0) * 60 + Number(m[3] ?? 0);
  return seconds > 60;
}

/**
 * The provider's quota is used up for longer than a run can wait (a
 * free tier's daily limit). Targets surface this so the run stops
 * instead of scoring every remaining attack as an error.
 */
export class QuotaExhaustedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'QuotaExhaustedError';
  }
}

// Next free call slot per endpoint+model, shared by every caller (the
// target and the mutator on the same model share one quota).
const nextSlot = new Map<string, number>();

async function pace(cfg: ModelConfig): Promise<void> {
  if (!cfg.rpm) return;
  const key = `${cfg.baseUrl}|${cfg.model}`;
  const now = Date.now();
  const at = Math.max(now, nextSlot.get(key) ?? 0);
  nextSlot.set(key, at + 60_000 / cfg.rpm);
  if (at > now) await new Promise((r) => setTimeout(r, at - now));
}

export interface RetryOptions {
  /** Retries after the first attempt. Default 3 */
  retries?: number;
  /** First backoff; doubles each retry. Default 2000ms */
  baseDelayMs?: number;
}

/**
 * One system + user turn against any configured provider. Retries
 * rate-limit and overload errors with exponential backoff, since hosted
 * free tiers return 429/503 under load and those would otherwise be
 * scored as errored attacks.
 */
export async function callModel(cfg: ModelConfig, opts: ModelCallOptions, retry: RetryOptions = {}): Promise<ModelResponse> {
  const retries = retry.retries ?? 3;
  const base = retry.baseDelayMs ?? 2000;
  for (let attempt = 0; ; attempt++) {
    await pace(cfg);
    try {
      if (PROVIDERS[cfg.provider]?.protocol === 'anthropic') {
        return await callAnthropic({ apiKey: cfg.apiKey!, model: cfg.model, ...opts });
      }
      return await callOpenAICompatible(cfg, opts);
    } catch (err) {
      const msg = (err as Error).message;
      if (RETRYABLE.test(msg) && isLongWait(msg)) throw new QuotaExhaustedError(msg);
      if (attempt >= retries || !RETRYABLE.test(msg)) throw err;
      await new Promise((r) => setTimeout(r, base * 2 ** attempt));
    }
  }
}

async function callOpenAICompatible(cfg: ModelConfig, opts: ModelCallOptions): Promise<ModelResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 30_000);

  let res: Response;
  try {
    res = await fetch(`${cfg.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(cfg.apiKey ? { Authorization: `Bearer ${cfg.apiKey}` } : {}),
      },
      body: JSON.stringify({
        model: cfg.model,
        max_tokens: opts.maxTokens ?? 1024,
        messages: [
          { role: 'system', content: opts.systemPrompt },
          { role: 'user', content: opts.userMessage },
        ],
        ...(cfg.reasoningEffort ? { reasoning_effort: cfg.reasoningEffort } : {}),
      }),
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  const label = PROVIDERS[cfg.provider]?.label ?? cfg.provider;
  if (!res.ok) {
    const errBody = await res.text().catch(() => '<no body>');
    throw new Error(`${label} API ${res.status}: ${errBody.replace(/\s+/g, ' ').slice(0, 500)}`);
  }

  let data: any = await res.json();
  // Some gateways wrap the response in a one-element array
  if (Array.isArray(data)) data = data[0];
  const choice = data?.choices?.[0];
  if (!choice) throw new Error(`${label} API returned no choices: ${JSON.stringify(data).slice(0, 300)}`);

  const content = choice.message?.content;
  const text = typeof content === 'string'
    ? content
    : Array.isArray(content)
      ? content.filter((p: any) => p?.type === 'text').map((p: any) => p.text).join('\n')
      : '';

  const inputTokens = data.usage?.prompt_tokens ?? 0;
  // Reasoning tokens are billed as output but some providers leave them
  // out of completion_tokens; total - prompt counts them either way.
  const completion = data.usage?.completion_tokens ?? 0;
  const total = data.usage?.total_tokens ?? 0;
  const outputTokens = Math.max(completion, total - inputTokens);

  return {
    text,
    inputTokens,
    outputTokens,
    model: data.model || cfg.model,
    stopReason: choice.finish_reason || 'unknown',
  };
}

/**
 * USD cost for a call, or null when the price is unknown. Unknown is
 * reported as unknown rather than $0 so a run never looks free by accident.
 */
export function estimateModelCost(cfg: Pick<ModelConfig, 'provider' | 'model'>, inputTokens: number, outputTokens: number): number | null {
  const preset = PROVIDERS[cfg.provider];
  if (preset?.free) return 0;
  if (preset?.protocol === 'anthropic' && MODEL_PRICING[cfg.model]) {
    return estimateAnthropicCost(cfg.model, inputTokens, outputTokens);
  }
  return null;
}
