import { config } from '../config'

// Provider-agnostic LLM client: any OpenAI-compatible /chat/completions endpoint
// (Groq, Gemini, Cerebras, OpenRouter, a local Ollama, …). Used ONLY to draft
// report narrative — scoring stays deterministic. Fail-soft: any error returns
// null so the caller falls back to the plain deterministic output.

const TIMEOUT_MS = 30_000

export function llmEnabled(): boolean {
  return config.llm.enabled
}

export async function llmComplete(system: string, user: string, maxTokens = 600): Promise<string | null> {
  if (!config.llm.enabled) return null
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(`${config.llm.baseUrl}/chat/completions`, {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(config.llm.apiKey ? { Authorization: `Bearer ${config.llm.apiKey}` } : {}),
      },
      body: JSON.stringify({
        model: config.llm.model,
        temperature: 0.2,
        max_tokens: maxTokens,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
      }),
    })
    if (!res.ok) return null
    const data = (await res.json()) as { choices?: { message?: { content?: string } }[] }
    const text = data.choices?.[0]?.message?.content
    return typeof text === 'string' && text.trim() ? text.trim() : null
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

// Same as llmComplete but asks the provider for a JSON object (OpenAI-style
// response_format) and parses it. Used for the structured intel advisor. Fail-
// soft: returns null on any error, non-JSON reply, or if the provider ignores
// response_format and wraps the object in prose/```json fences (we salvage the
// first {...} block before giving up).
export async function llmCompleteJson<T = unknown>(system: string, user: string, maxTokens = 1200): Promise<T | null> {
  if (!config.llm.enabled) return null
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(`${config.llm.baseUrl}/chat/completions`, {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(config.llm.apiKey ? { Authorization: `Bearer ${config.llm.apiKey}` } : {}),
      },
      body: JSON.stringify({
        model: config.llm.model,
        temperature: 0.2,
        max_tokens: maxTokens,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
      }),
    })
    if (!res.ok) return null
    const data = (await res.json()) as { choices?: { message?: { content?: string } }[] }
    const text = data.choices?.[0]?.message?.content
    if (typeof text !== 'string' || !text.trim()) return null
    try {
      return JSON.parse(text) as T
    } catch {
      const m = text.match(/\{[\s\S]*\}/)
      if (m) {
        try {
          return JSON.parse(m[0]) as T
        } catch {
          return null
        }
      }
      return null
    }
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}
