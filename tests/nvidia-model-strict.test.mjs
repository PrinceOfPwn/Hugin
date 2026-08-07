import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { NvidiaModelsClient } from "../scripts/lib/nvidia-models.mjs";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "hugin-nvidia-strict-"));
const originalFetch = globalThis.fetch;
const seenModels = [];

globalThis.fetch = async (_url, options) => {
  const body = JSON.parse(options.body);
  seenModels.push(body.model);
  return new Response(JSON.stringify({ error: "fixture rejection" }), {
    status: 400,
    headers: { "content-type": "application/json" },
  });
};

try {
  const client = new NvidiaModelsClient({
    apiKey: "fixture-key",
    cacheDir: tmp,
    model: "z-ai/glm-5.2",
    allowFallbacks: false,
  });
  const result = await client.completeJson({
    messages: [{ role: "user", content: "fixture" }],
    validate: () => [],
    maxTokens: 32,
    force: true,
  });

  assert.equal(result.value, null);
  assert.equal(seenModels.length, 2, "strict mode should try GLM's JSON and plain response formats only");
  assert.deepEqual([...new Set(seenModels)], ["z-ai/glm-5.2"], "strict mode must never call the fallback model");
  console.log("[nvidia-model-strict] GLM-only mode never invoked a fallback model — OK");
} finally {
  globalThis.fetch = originalFetch;
  fs.rmSync(tmp, { recursive: true, force: true });
}
