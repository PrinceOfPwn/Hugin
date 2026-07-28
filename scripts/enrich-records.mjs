#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { sanitize } from "./lib/sanitize.mjs";
import {
  ENRICHMENT_JSON_SCHEMA,
  ENRICHMENT_VERSION,
  evidenceExists,
  normalizeWhitespace,
  readJsonl,
  writeJsonl,
} from "./lib/ingest-contract.mjs";
import { GitHubModelsClient } from "./lib/github-models.mjs";
import { LocalTextModel } from "./lib/local-model.mjs";
import {
  LOCAL_SIMPLE_ENRICHMENT_SYSTEM_PROMPT,
  REMOTE_ENRICHMENT_SYSTEM_PROMPT,
  remoteEnrichmentUserPrompt,
  remoteRepairPrompt,
} from "./lib/prompts.mjs";

const inputArg = process.argv[2];
if (!inputArg) {
  console.error("Usage: node scripts/enrich-records.mjs <canonical.jsonl>");
  process.exit(1);
}

const input = path.resolve(inputArg);
const base = path.basename(input, ".jsonl");
const output = path.resolve("data/enriched", `${base}.jsonl`);
const reportPath = path.resolve("data/enriched", `${base}.report.json`);
const policyPath = path.resolve("scripts/ingest-model-policy.json");
const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
const { records } = readJsonl(input);
const canonical = records.map(({ value }) => value);
const byId = new Map(canonical.map((record) => [record.id, record]));
const enrichedById = new Map();
const report = { local: 0, remote: 0, remote_cache: 0, degraded: 0, remote_errors: [] };

const local = new LocalTextModel({
  modelId: process.env.HUGIN_SIMPLE_MODEL ?? process.env.HUGIN_DETECT_MODEL ?? "onnx-community/gemma-4-E2B-it-ONNX",
  cacheDir: process.env.HUGIN_MODEL_CACHE ?? ".hf-cache",
  maxNewTokens: 500,
});

const remote = new GitHubModelsClient({
  token: process.env.GITHUB_TOKEN,
  cacheDir: process.env.HUGIN_REMOTE_CACHE ?? ".cache/hugin-models",
  policy,
});

const simpleRecords = canonical.filter((record) => record.routing.semantic_complexity === "simple");
const remoteRecords = canonical.filter((record) => record.routing.semantic_complexity !== "simple");

try {
  for (const record of simpleRecords) {
    const enrichment = await enrichSimple(record, local);
    enrichedById.set(record.id, enrichment);
    report.local++;
  }

  const batches = makeBatches(remoteRecords, policy.batch.max_records, policy.batch.max_input_chars);
  for (const batch of batches) {
    const tier = batch.some((record) => record.routing.semantic_complexity === "complex") ? "high" : "low";
    const route = tier === "high" ? policy.complex : policy.general;
    const models = remote.available ? await remote.selectModels({ tier: route.tier, preferred: route.preferred }) : [];

    const result = models.length
      ? await remote.completeStructured({
          models,
          messages: [
            { role: "system", content: REMOTE_ENRICHMENT_SYSTEM_PROMPT },
            { role: "user", content: remoteEnrichmentUserPrompt(batch) },
          ],
          jsonSchema: ENRICHMENT_JSON_SCHEMA,
          validate: (value) => validateBatch(value, batch),
          repairMessages: (raw, errors) => [
            { role: "system", content: REMOTE_ENRICHMENT_SYSTEM_PROMPT },
            { role: "user", content: remoteRepairPrompt(raw, errors, batch) },
          ],
          maxTokens: route.max_output_tokens,
        })
      : { value: null, errors: [remote.available ? "No catalog model matched policy" : "GITHUB_TOKEN unavailable"] };

    if (result.value) {
      for (const item of result.value.items) {
        enrichedById.set(item.id, filterGroundedEnrichment(byId.get(item.id), item, policy.thresholds, {
          status: "complete",
          provider: "github-models",
          model: result.model,
          cached: Boolean(result.cached),
        }));
      }
      report.remote += batch.length;
      if (result.cached) report.remote_cache += batch.length;
    } else {
      report.remote_errors.push(...result.errors);
      for (const record of batch) {
        const fallback = await enrichSimple(record, local, "degraded");
        enrichedById.set(record.id, fallback);
        report.degraded++;
      }
    }
  }
} finally {
  await local.dispose();
}

const outputRecords = canonical.map((record) => ({
  ...record,
  enrichment: enrichedById.get(record.id) ?? deterministicFallback(record, "degraded"),
}));

writeJsonl(output, outputRecords);
fs.writeFileSync(reportPath, `${JSON.stringify({ input: path.relative(process.cwd(), input), output: path.relative(process.cwd(), output), ...report }, null, 2)}\n`);
console.log(`Enriched ${outputRecords.length} records -> ${output}`);
console.log(JSON.stringify(report, null, 2));

async function enrichSimple(record, model, status = "complete") {
  try {
    const prompt = JSON.stringify({ id: record.id, kind: record.kind, title: record.title, content: record.content, facets: record.facets ?? {} }, null, 2);
    const result = await model.generateJson({
      system: LOCAL_SIMPLE_ENRICHMENT_SYSTEM_PROMPT,
      user: prompt,
      maxNewTokens: 500,
    });
    const parsed = result.parsed;
    if (!parsed || typeof parsed.summary !== "string" || typeof parsed.abstract !== "string") return deterministicFallback(record, "degraded");
    const entities = Array.isArray(parsed.entities) ? parsed.entities.filter((item) => item && evidenceExists(record, item.evidence)).map((item) => ({
      name: String(item.name ?? "").trim(),
      type: String(item.type ?? "other").trim(),
      confidence: 0.65,
      evidence: [String(item.evidence)],
    })).filter((item) => item.name) : [];
    return sanitize({
      schema_version: ENRICHMENT_VERSION,
      status,
      provider: "local",
      model: model.modelId,
      summary: String(parsed.summary).slice(0, 600),
      abstract: String(parsed.abstract).slice(0, 1600),
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
    schema_version: ENRICHMENT_VERSION,
    status,
    provider: "deterministic",
    model: null,
    summary: summary || record.title,
    abstract: summary || record.title,
    tags: [record.kind, record.category, record.language, ...(record.tags ?? [])].filter(Boolean).slice(0, 16),
    concepts: [], techniques: [], entities: [], relations: [], mitre_candidates: [],
  });
}

function makeBatches(records, maxRecords, maxChars) {
  const batches = [];
  let current = [];
  let chars = 0;
  for (const record of records) {
    const size = JSON.stringify(record).length;
    if (current.length && (current.length >= maxRecords || chars + size > maxChars)) {
      batches.push(current);
      current = [];
      chars = 0;
    }
    current.push(record);
    chars += size;
  }
  if (current.length) batches.push(current);
  return batches;
}

function validateBatch(value, batch) {
  const errors = [];
  if (!value || typeof value !== "object" || !Array.isArray(value.items)) return ["items array is required"];
  const expected = new Set(batch.map((record) => record.id));
  const seen = new Set();
  for (const item of value.items) {
    if (!expected.has(item?.id)) errors.push(`unexpected id ${item?.id}`);
    if (seen.has(item?.id)) errors.push(`duplicate id ${item?.id}`);
    seen.add(item?.id);
    for (const field of ["summary", "abstract"]) if (typeof item?.[field] !== "string") errors.push(`${item?.id}.${field} must be string`);
    for (const field of ["tags", "concepts", "techniques", "entities", "relations", "mitre_candidates"]) if (!Array.isArray(item?.[field])) errors.push(`${item?.id}.${field} must be array`);
  }
  for (const id of expected) if (!seen.has(id)) errors.push(`missing id ${id}`);
  return errors;
}

function filterGroundedEnrichment(record, item, thresholds, metadata) {
  const grounded = (items, threshold) => (Array.isArray(items) ? items : []).filter((candidate) => {
    if (typeof candidate?.confidence !== "number" || candidate.confidence < threshold) return false;
    if (!Array.isArray(candidate.evidence) || candidate.evidence.length === 0) return false;
    return candidate.evidence.every((quote) => evidenceExists(record, quote));
  });

  return sanitize({
    schema_version: ENRICHMENT_VERSION,
    ...metadata,
    summary: item.summary,
    abstract: item.abstract,
    tags: [...new Set((item.tags ?? []).map((tag) => normalizeWhitespace(tag)).filter(Boolean))].slice(0, 16),
    concepts: grounded(item.concepts, thresholds.claim),
    techniques: grounded(item.techniques, thresholds.technique),
    entities: grounded(item.entities, thresholds.entity),
    relations: grounded(item.relations, thresholds.relation),
    mitre_candidates: grounded(item.mitre_candidates, thresholds.mitre),
  });
}
