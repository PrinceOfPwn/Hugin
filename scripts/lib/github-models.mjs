import fs from "node:fs";
import path from "node:path";
import { sha256 } from "./ingest-contract.mjs";
import { parseJsonObject } from "./local-model.mjs";

const API_BASE = "https://models.github.ai";
const API_VERSION = "2026-03-10";

function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

export class GitHubModelsClient {
  constructor({ token = process.env.GITHUB_TOKEN, cacheDir = ".cache/hugin-models", policy = {} } = {}) {
    this.token = token;
    this.cacheDir = path.resolve(cacheDir);
    this.policy = policy;
    fs.mkdirSync(this.cacheDir, { recursive: true });
  }

  get available() { return Boolean(this.token); }

  headers() {
    return {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${this.token}`,
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": API_VERSION,
    };
  }

  async catalog() {
    const cacheFile = path.join(this.cacheDir, "catalog.json");
    if (fs.existsSync(cacheFile)) {
      const age = Date.now() - fs.statSync(cacheFile).mtimeMs;
      if (age < 6 * 60 * 60 * 1000) return JSON.parse(fs.readFileSync(cacheFile, "utf8"));
    }
    if (!this.available) return [];
    const response = await fetch(`${API_BASE}/catalog/models`, { headers: this.headers() });
    if (!response.ok) throw new Error(`GitHub Models catalog failed: ${response.status} ${await response.text()}`);
    const models = await response.json();
    fs.writeFileSync(cacheFile, JSON.stringify(models, null, 2));
    return models;
  }

  async selectModels({ tier, preferred = [] }) {
    const catalog = await this.catalog();
    const byId = new Map(catalog.map((model) => [model.id, model]));
    const selected = [];
    for (const id of preferred) if (byId.has(id)) selected.push(id);
    for (const model of catalog) {
      if (selected.includes(model.id)) continue;
      if (model.rate_limit_tier !== tier) continue;
      if (!model.supported_input_modalities?.includes("text")) continue;
      if (!model.supported_output_modalities?.includes("text")) continue;
      selected.push(model.id);
    }
    return selected.slice(0, 6);
  }

  async completeStructured({ models, messages, jsonSchema, validate, repairMessages, maxTokens = 2200 }) {
    const errors = [];
    for (const model of models) {
      const cacheKey = sha256(JSON.stringify({ model, messages, jsonSchema, maxTokens }));
      const cacheFile = path.join(this.cacheDir, `${cacheKey}.json`);
      if (fs.existsSync(cacheFile)) {
        const cached = JSON.parse(fs.readFileSync(cacheFile, "utf8"));
        const cachedErrors = validate(cached);
        if (cachedErrors.length === 0) return { value: cached, model, cached: true, errors };
      }

      const first = await this.#callModel({ model, messages, jsonSchema, maxTokens });
      if (first.ok) {
        const validationErrors = validate(first.value);
        if (validationErrors.length === 0) {
          fs.writeFileSync(cacheFile, JSON.stringify(first.value, null, 2));
          return { value: first.value, model, cached: false, errors };
        }
        errors.push(`${model}: ${validationErrors.join("; ")}`);

        if (repairMessages) {
          const repaired = await this.#callModel({
            model,
            messages: repairMessages(first.raw, validationErrors),
            jsonSchema,
            maxTokens,
          });
          if (repaired.ok) {
            const repairedErrors = validate(repaired.value);
            if (repairedErrors.length === 0) {
              fs.writeFileSync(cacheFile, JSON.stringify(repaired.value, null, 2));
              return { value: repaired.value, model, cached: false, repaired: true, errors };
            }
            errors.push(`${model} repair: ${repairedErrors.join("; ")}`);
          } else {
            errors.push(`${model} repair request: ${repaired.error}`);
          }
        }
      } else {
        errors.push(`${model}: ${first.error}`);
      }
    }
    return { value: null, model: null, cached: false, errors };
  }

  async #callModel({ model, messages, jsonSchema, maxTokens }) {
    const formats = [
      { type: "json_schema", json_schema: jsonSchema },
      { type: "json_object" },
    ];

    for (const responseFormat of formats) {
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          const response = await fetch(`${API_BASE}/inference/chat/completions`, {
            method: "POST",
            headers: this.headers(),
            body: JSON.stringify({
              model,
              messages,
              response_format: responseFormat,
              temperature: 0,
              max_tokens: maxTokens,
              seed: 7,
            }),
          });

          if (response.ok) {
            const payload = await response.json();
            const raw = payload?.choices?.[0]?.message?.content ?? "";
            const value = parseJsonObject(raw);
            if (!value) return { ok: false, error: "model returned non-JSON content", raw };
            return { ok: true, value, raw };
          }

          const text = await response.text();
          if (response.status === 422 && responseFormat.type === "json_schema") break;
          if (response.status === 429 || response.status >= 500) {
            const retryAfter = Number(response.headers.get("retry-after") ?? 0);
            await sleep(retryAfter > 0 ? retryAfter * 1000 : (attempt + 1) * 2500);
            continue;
          }
          return { ok: false, error: `${response.status} ${text.slice(0, 800)}` };
        } catch (error) {
          if (attempt === 2) return { ok: false, error: String(error?.message ?? error) };
          await sleep((attempt + 1) * 2000);
        }
      }
    }
    return { ok: false, error: "all response formats failed" };
  }
}
