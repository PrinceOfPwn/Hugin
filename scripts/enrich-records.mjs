#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { sanitize } from "./lib/sanitize.mjs";
import {
  ENRICHMENT_JSON_SCHEMA,
  ENRICHMENT_VERSION,
  evidenceExists,
  filterGroundedEnrichment,
  normalizeWhitespace,
  readJsonl,
  writeJsonl,
} from "./lib/ingest-contract.mjs";
import { LocalTextModel } from "./lib/local-model.mjs";
import { NvidiaModelsClient } from "./lib/nvidia-models.mjs";
import {
  LOCAL_SIMPLE_ENRICHMENT_SYSTEM_PROMPT,
  REMOTE_ENRICHMENT_SYSTEM_PROMPT,
  remoteEnrichmentUserPrompt,
  remoteRepairPrompt,
} from "./lib/prompts.mjs";

const argv = process.argv.slice(2);
const force = argv.includes("--force");
const inputArg = argv.find((arg) => !arg.startsWith("--"));
if (!inputArg) {
  console.error("Usage: node scripts/enrich-records.mjs <canonical.jsonl> [--force]");
  process.exit(1);
}

const input = path.resolve(inputArg);
const base = path.basename(input, ".jsonl");
const output = path.resolve("data/enriched", `${base}.jsonl`);
const reportPath = path.resolve("data/enriched", `${base}.report.json`);
const policy = JSON.parse(fs.readFileSync(path.resolve("scripts/ingest-model-policy.json"), "utf8"));
const { records } = readJsonl(input);
const canonical = records.map(({ value }) => value);
const enrichedById = new Map();
const report = { local: 0, remote: 0, remote_cache: 0, skipped: 0, degraded: 0, remote_errors: [] };

const skipped = canonical.filter((record) => (record.routing?.requested_enrichment?.length ?? 0) === 0);
const requested = canonical.filter((record) => !skipped.includes(record));
const complex = requested.filter((record) => record.routing?.semantic_complexity === "complex");
const localRecords = requested.filter((record) => record.routing?.semantic_complexity !== "complex");
const local = localRecords.length
  ? new LocalTextModel({
      modelId: process.env.HUGIN_SIMPLE_MODEL ?? policy.local.model,
      cacheDir: process.env.HUGIN_MODEL_CACHE ?? ".hf-cache",
      dtype: process.env.HUGIN_SIMPLE_DTYPE ?? policy.local.dtype ?? "q4",
      maxNewTokens: policy.local.max_output_tokens ?? 700,
    })
  : null;
const cloud = new NvidiaModelsClient({
  cacheDir: process.env.HUGIN_NVIDIA_CACHE ?? ".cache/nvidia-models",
  model: process.env.HUGIN_NVIDIA_MODEL ?? policy.complex.model,
});

try {
  for (const record of skipped) {
    enrichedById.set(record.id, deterministicFallback(record, "not_requested"));
    report.skipped++;
  }

  for (const record of localRecords) {
    enrichedById.set(record.id, await enrichSimple(record, local));
    report.local++;
  }

  for (const batch of makeBatches(complex, policy.batch?.complex?.max_records ?? 2, policy.batch?.complex?.max_input_chars ?? 16000)) {
    const result = await cloud.completeJson({
      messages: [
        { role: "system", content: REMOTE_ENRICHMENT_SYSTEM_PROMPT },
        { role: "user", content: remoteEnrichmentUserPrompt(batch) },
      ],
      validate: (value) => validateBatch(value, batch),
      repairMessages: (raw, errors) => [
        { role: "system", content: REMOTE_ENRICHMENT_SYSTEM_PROMPT },
        { role: "user", content: remoteRepairPrompt(raw, errors, batch) },
      ],
      maxTokens: policy.complex.max_output_tokens ?? 4000,
      force,
    });
    if (result.value) {
      for (const item of result.value.items) {
        const grounded = filterGroundedEnrichment(batch.find((record) => record.id === item.id), item, policy.thresholds, {
          status: "complete", provider: "nvidia", model: result.model, cached: Boolean(result.cached),
        });
        // filterGroundedEnrichment returns a canonical record. Persist only its
        // stable enrichment payload; nesting the whole record was the V2 bug.
        enrichedById.set(item.id, grounded.enrichment);
      }
      report.remote += batch.length;
      if (result.cached) report.remote_cache += batch.length;
    } else {
      report.remote_errors.push(...result.errors);
      for (const record of batch) {
        enrichedById.set(record.id, deterministicFallback(record, "degraded"));
        report.degraded++;
      }
    }
  }
} finally {
  await local?.dispose();
}

const outputRecords = canonical.map((record) => ({
  ...record,
  enrichment: enrichedById.get(record.id) ?? deterministicFallback(record, "degraded"),
}));
writeJsonl(output, outputRecords);
fs.writeFileSync(reportPath, `${JSON.stringify({ input: path.relative(process.cwd(), input), output: path.relative(process.cwd(), output), ...report }, null, 2)}\n`);
console.log(`Enriched ${outputRecords.length} records -> ${output}`);
console.log(JSON.stringify(report, null, 2));

async function enrichSimple(record, model) {
  try {
    const prompt = JSON.stringify({ id: record.id, kind: record.kind, title: record.title, content: record.content, facets: record.facets ?? {} }, null, 2);
    const result = await model.generateJson({ system: LOCAL_SIMPLE_ENRICHMENT_SYSTEM_PROMPT, user: prompt, maxNewTokens: policy.local.max_output_tokens ?? 700 });
    const parsed = result.parsed;
    if (!parsed || typeof parsed.summary !== "string" || typeof parsed.abstract !== "string") return deterministicFallback(record, "degraded");
    const entities = Array.isArray(parsed.entities) ? parsed.entities.filter((item) => item && evidenceExists(record, item.evidence)).map((item) => ({
      name: String(item.name ?? "").trim(), type: String(item.type ?? "other").trim(), confidence: 0.65, evidence: [String(item.evidence)],
    })).filter((item) => item.name) : [];
    return sanitize({
      schema_version: ENRICHMENT_VERSION, status: "complete", provider: "local-qwen", model: model.modelId,
      summary: String(parsed.summary).slice(0, 600), abstract: String(parsed.abstract).slice(0, 1600),
      tags: Array.isArray(parsed.tags) ? parsed.tags.map((tag) => normalizeWhitespace(tag)).filter(Boolean).slice(0, 16) : [],
      concepts: [], techniques: [], relations: [], mitre_candidates: [], entities,
    });
  } catch {
    return deterministicFallback(record, "degraded");
  }
}

function deterministicFallback(record, status) {
  const summary = normalizeWhitespace(record.content).slice(0, 420);
  return sanitize({
    schema_version: ENRICHMENT_VERSION, status, provider: "deterministic", model: null,
    summary: summary || record.title, abstract: summary || record.title,
    tags: [record.kind, record.category, record.language, ...(record.tags ?? [])].filter(Boolean).slice(0, 16),
    concepts: [], techniques: [], entities: [], relations: [], mitre_candidates: [],
  });
}

function makeBatches(records, maxRecords, maxChars) {
  const batches = []; let current = []; let chars = 0;
  for (const record of records) {
    const size = JSON.stringify(record).length;
    if (current.length && (current.length >= maxRecords || chars + size > maxChars)) { batches.push(current); current = []; chars = 0; }
    current.push(record); chars += size;
  }
  if (current.length) batches.push(current);
  return batches;
}

function validateBatch(value, batch) {
  const errors = [];
  if (!value || typeof value !== "object" || !Array.isArray(value.items)) return ["items array is required"];
  const expected = new Set(batch.map((record) => record.id)); const seen = new Set();
  for (const item of value.items) {
    if (!expected.has(item?.id)) errors.push(`unexpected id ${item?.id}`);
    if (seen.has(item?.id)) errors.push(`duplicate id ${item?.id}`); seen.add(item?.id);
    for (const field of ["summary", "abstract"]) if (typeof item?.[field] !== "string") errors.push(`${item?.id}.${field} must be string`);
    for (const field of ["tags", "concepts", "techniques", "entities", "relations", "mitre_candidates"]) if (!Array.isArray(item?.[field])) errors.push(`${item?.id}.${field} must be array`);
  }
  for (const id of expected) if (!seen.has(id)) errors.push(`missing id ${id}`);
  return errors;
}
