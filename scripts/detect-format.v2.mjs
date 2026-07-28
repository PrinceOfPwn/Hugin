#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { buildStructuralProfile, ROUTER_VERSION, sha256, validateRouterMapping } from "./lib/ingest-contract.mjs";
import { NvidiaModelsClient } from "./lib/nvidia-models.mjs";
import { classifyKnownSchema, deterministicFallback } from "./lib/schema-router.mjs";
import { ROUTER_SYSTEM_PROMPT, routerRepairPrompt, routerUserPrompt } from "./lib/prompts.mjs";

const argv = process.argv.slice(2);
const inputArg = argv.find((arg) => !arg.startsWith("--"));
const force = argv.includes("--force");
if (!inputArg) {
  console.error("Usage: node scripts/detect-format.v2.mjs <input.jsonl> [--force]");
  process.exit(1);
}

const input = path.resolve(inputArg);
const mappingPath = input.replace(/\.jsonl$/i, ".mapping.json");
const modelId = process.env.HUGIN_NVIDIA_ROUTER_MODEL ?? process.env.HUGIN_NVIDIA_MODEL ?? "z-ai/glm-5.2";
if (!fs.existsSync(input)) throw new Error(`Input not found: ${input}`);
const raw = fs.readFileSync(input, "utf8");
const inputHash = sha256(raw);

if (!force && fs.existsSync(mappingPath)) {
  try {
    const current = JSON.parse(fs.readFileSync(mappingPath, "utf8"));
    const currentAndValid = current?._detected?.input_sha256 === inputHash
      && current?._detected?.router_version === ROUTER_VERSION
      && current?._detected?.model === modelId
      && validateRouterMapping(current).length === 0;
    if (currentAndValid) {
      console.log(`Mapping is current: ${mappingPath}`);
      process.exit(0);
    }
  } catch {}
}

const parsedRecords = [];
for (const line of raw.split("\n")) {
  if (!line.trim()) continue;
  try { parsedRecords.push(JSON.parse(line)); } catch {}
}
if (parsedRecords.length === 0) throw new Error("No parseable JSONL records found");

const sourceName = path.basename(input, ".jsonl");
const profile = buildStructuralProfile(parsedRecords);
let output = classifyKnownSchema(parsedRecords, sourceName);
let route = output ? "deterministic-schema" : "nvidia-cloud";

if (!output) {
  const cloud = new NvidiaModelsClient({ cacheDir: process.env.HUGIN_NVIDIA_CACHE ?? ".cache/nvidia-models", model: modelId });
  const result = await cloud.completeJson({
    messages: [
      { role: "system", content: ROUTER_SYSTEM_PROMPT },
      { role: "user", content: routerUserPrompt(profile) },
    ],
    validate: validateRouterMapping,
    repairMessages: (rawOutput, errors) => [
      { role: "system", content: ROUTER_SYSTEM_PROMPT },
      { role: "user", content: routerRepairPrompt(rawOutput, errors, profile) },
    ],
    maxTokens: 1200,
    force,
  });
  output = result.value;
  if (!output) {
    route = "deterministic-fallback";
    console.warn(`Cloud schema routing unavailable; preserving input without guessed semantics: ${result.errors.join("; ")}`);
    output = deterministicFallback(parsedRecords, sourceName);
  }
}

output._detected = {
  input: path.relative(process.cwd(), input),
  input_records: parsedRecords.length,
  input_sha256: inputHash,
  schema_fingerprint: sha256(JSON.stringify(profile.paths)).slice(0, 24),
  router_version: ROUTER_VERSION,
  model: modelId,
  route,
  detected_at: new Date().toISOString(),
};

const errors = validateRouterMapping(output);
if (errors.length) throw new Error(`Router produced an invalid mapping: ${errors.join("; ")}`);
fs.writeFileSync(mappingPath, `${JSON.stringify(output, null, 2)}\n`);
console.log(`Mapping written: ${mappingPath}`);
console.log(`  route: ${route}`);
console.log(`  kind: ${output.kind}`);
console.log(`  complexity: ${output.semantic_complexity}`);
console.log(`  confidence: ${output.confidence}`);
