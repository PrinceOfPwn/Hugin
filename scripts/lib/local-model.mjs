import path from "node:path";

export class LocalTextModel {
  constructor({ modelId, cacheDir, dtype = "q4", maxNewTokens = 800 }) {
    this.modelId = modelId;
    this.cacheDir = path.resolve(cacheDir);
    this.dtype = dtype;
    this.maxNewTokens = maxNewTokens;
    this.generator = null;
  }

  async load() {
    if (this.generator) return;
    const { env, pipeline } = await import("@huggingface/transformers");
    env.cacheDir = this.cacheDir;
    env.useFSCache = true;
    env.allowRemoteModels = true;
    this.generator = await pipeline("text-generation", this.modelId, { dtype: this.dtype, device: "cpu" });
  }

  async generateJson({ system, user, maxNewTokens = this.maxNewTokens }) {
    await this.load();
    const result = await this.generator([
      { role: "system", content: system },
      { role: "user", content: user },
    ], {
      max_new_tokens: maxNewTokens,
      do_sample: false,
      temperature: 0,
      repetition_penalty: 1.05,
      chat_template_kwargs: { enable_thinking: false },
    });
    const generated = result?.[0]?.generated_text;
    const text = Array.isArray(generated)
      ? generated.findLast((message) => message?.role === "assistant")?.content ?? ""
      : String(generated ?? "");
    return { raw: text, parsed: parseJsonObject(text) };
  }

  async dispose() {
    try { await this.generator?.dispose?.(); } catch {}
    this.generator = null;
  }
}

export function parseJsonObject(text) {
  const cleaned = String(text ?? "").trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "").trim();
  try { return JSON.parse(cleaned); } catch {}
  // Models occasionally add a short preface, a Markdown fence, or a second
  // JSON-looking fragment. Try every balanced object rather than slicing from
  // the first brace to the last, which corrupts otherwise valid output.
  for (let start = 0; start < cleaned.length; start++) {
    if (cleaned[start] !== "{") continue;
    let depth = 0;
    let quoted = false;
    let escaped = false;
    for (let end = start; end < cleaned.length; end++) {
      const char = cleaned[end];
      if (quoted) {
        if (escaped) escaped = false;
        else if (char === "\\") escaped = true;
        else if (char === '"') quoted = false;
        continue;
      }
      if (char === '"') { quoted = true; continue; }
      if (char === "{") depth++;
      if (char === "}") depth--;
      if (depth === 0) {
        try { return JSON.parse(cleaned.slice(start, end + 1)); } catch { break; }
      }
    }
  }
  return null;
}
