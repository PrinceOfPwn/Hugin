import fs from "node:fs";
import path from "node:path";
import { sha256 } from "./ingest-contract.mjs";
import { parseJsonObject } from "./local-model.mjs";

const DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1";
const DEFAULT_MODEL = "z-ai/glm-5.2";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Minimal OpenAI-compatible client for NVIDIA Integrate. The key is only read
 * from the environment, never written to a report, cache key, or artifact. */
export class NvidiaModelsClient {
  constructor({ apiKey = process.env.NVIDIA_API_KEY, baseUrl = process.env.NVIDIA_API_BASE_URL ?? DEFAULT_BASE_URL, cacheDir = ".cache/nvidia-models", model = process.env.HUGIN_NVIDIA_MODEL ?? DEFAULT_MODEL } = {}) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.cacheDir = path.resolve(cacheDir);
    this.model = model;
    fs.mkdirSync(this.cacheDir, { recursive: true });
  }

  get available() { return Boolean(this.apiKey); }

  async completeJson({ messages, validate, repairMessages, maxTokens = 131072, force = false, model = this.model }) {
    if (!this.available) return { value: null, model: null, cached: false, errors: ["NVIDIA_API_KEY unavailable"] };
    const cacheFile = path.join(this.cacheDir, `${sha256(JSON.stringify({ provider: "nvidia", model, messages, maxTokens })).slice(0, 48)}.json`);
    if (!force && fs.existsSync(cacheFile)) {
      try {
        const cached = JSON.parse(fs.readFileSync(cacheFile, "utf8"));
        if (validate(cached).length === 0) return { value: cached, model, cached: true, errors: [] };
      } catch {}
    }

    const first = await this.#call({ model, messages, maxTokens });
    const errors = [];
    if (first.ok) {
      const validationErrors = validate(first.value);
      if (validationErrors.length === 0) {
        fs.writeFileSync(cacheFile, JSON.stringify(first.value, null, 2));
        return { value: first.value, model, cached: false, errors };
      }
      errors.push(`${model}: ${validationErrors.join("; ")}`);
      if (repairMessages) {
        const repaired = await this.#call({ model, messages: repairMessages(first.raw, validationErrors), maxTokens });
        if (repaired.ok && validate(repaired.value).length === 0) {
          fs.writeFileSync(cacheFile, JSON.stringify(repaired.value, null, 2));
          return { value: repaired.value, model, cached: false, repaired: true, errors };
        }
        errors.push(repaired.ok ? `${model}: repair remained invalid` : `${model}: repair ${repaired.error}`);
      }
    } else {
      errors.push(`${model}: ${first.error}`);
      if (repairMessages && first.raw) {
        const repaired = await this.#call({ model, messages: repairMessages(first.raw, [first.error]), maxTokens });
        if (repaired.ok && validate(repaired.value).length === 0) {
          fs.writeFileSync(cacheFile, JSON.stringify(repaired.value, null, 2));
          return { value: repaired.value, model, cached: false, repaired: true, errors };
        }
        errors.push(repaired.ok ? `${model}: repair remained invalid` : `${model}: repair ${repaired.error}`);
      }
    }
    return { value: null, model: null, cached: false, errors };
  }

  async #call({ model, messages, maxTokens }) {
    const modelConfigs = [
      {
        model: "z-ai/glm-5.2",
        temperature: 1,
        top_p: 1,
        max_tokens: maxTokens || 131072,
        seed: 42,
      },
      {
        model: "deepseek-ai/deepseek-v4-pro",
        temperature: 1,
        top_p: 0.95,
        max_tokens: maxTokens || 131072,
        chat_template_kwargs: { thinking: false },
      },
    ];

    if (model && model !== "z-ai/glm-5.2" && model !== "deepseek-ai/deepseek-v4-pro") {
      modelConfigs.unshift({
        model,
        temperature: 1,
        top_p: 1,
        max_tokens: maxTokens || 131072,
      });
    }

    let lastError = "";

    for (const config of modelConfigs) {
      const currentModel = config.model;
      const bodies = [
        { ...config, messages, response_format: { type: "json_object" } },
        { ...config, messages },
      ];
      for (const body of bodies) {
        for (let attempt = 0; attempt < 5; attempt++) {
          try {
            const response = await fetch(`${this.baseUrl}/chat/completions`, {
              method: "POST",
              headers: { Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json" },
              body: JSON.stringify(body),
            });
            const text = await response.text();
            if (response.ok) {
              const raw = JSON.parse(text)?.choices?.[0]?.message?.content ?? "";
              const value = parseJsonObject(raw);
              return value ? { ok: true, value, raw } : { ok: false, error: `${currentModel}: model returned non-JSON content`, raw };
            }
            lastError = `${currentModel}: ${response.status} ${text.slice(0, 300)}`;
            if (response.status === 400 || response.status === 404 || response.status === 422) break;
            if (response.status === 429 || response.status >= 500) {
              await sleep(Math.pow(2, attempt) * 2000);
              continue;
            }
            return { ok: false, error: lastError };
          } catch (error) {
            lastError = `${currentModel}: ${String(error?.message ?? error)}`;
            if (attempt === 4) break;
            await sleep(Math.pow(2, attempt) * 2000);
          }
        }
      }
    }
    return { ok: false, error: `all NVIDIA response formats failed (${lastError})` };
  }
}
