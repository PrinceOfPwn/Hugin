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
  REMOTE_ENRICHMENT_FEW_SHOTS,
  REMOTE_ENRICHMENT_SYSTEM_PROMPT,
  remoteEnrichmentUserPrompt,
  remoteRepairPrompt,
} from "./lib/prompts.mjs";

const argv = process.argv.slice(2);
const force = argv.includes("--force");
const inputArgs = argv.filter((arg) => !arg.startsWith("--"));
if (inputArgs.length === 0) {
  console.error("Usage: node scripts/enrich-records.mjs <canonical.jsonl> [more.jsonl ...] [--force]");
  process.exit(1);
}

const policy = JSON.parse(fs.readFileSync(new URL("./ingest-model-policy.json", import.meta.url), "utf8"));
const jobs = inputArgs.map((inputArg) => {
  const input = path.resolve(inputArg);
  const base = path.basename(input, ".jsonl");
  const { records } = readJsonl(input);
  return {
    input,
    output: path.resolve("data/enriched", `${base}.jsonl`),
    reportPath: path.resolve("data/enriched", `${base}.report.json`),
    canonical: records.map(({ value }) => value),
  };
});
const needsLocalModel = jobs.some(({ canonical }) => canonical.some((record) =>
  (record.routing?.requested_enrichment?.length ?? 0) > 0
  && record.routing?.semantic_complexity !== "complex"
));
const local = needsLocalModel
  ? new LocalTextModel({
      modelId: process.env.HUGIN_SIMPLE_MODEL ?? policy.local.model,
      revision: process.env.HUGIN_SIMPLE_REVISION ?? policy.local.revision ?? "main",
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
  console.log(`[enrich] batch start: ${jobs.length} file(s); shared local model=${needsLocalModel ? "enabled" : "not needed"}`);
  for (let index = 0; index < jobs.length; index++) {
    const job = jobs[index];
    console.log(`[enrich] file ${index + 1}/${jobs.length}: ${path.relative(process.cwd(), job.input)}`);
    const report = await enrichJob(job);
    if (process.env.HUGIN_FAIL_ON_DEGRADED === "true" && report.degraded > 0) {
      throw new Error(`Strict enrichment gate rejected ${report.degraded} degraded record(s) in ${path.basename(job.input)}; inspect ${path.relative(process.cwd(), job.reportPath)}`);
    }
  }
} finally {
  await local?.dispose();
}

async function enrichJob({ input, output, reportPath, canonical }) {
  const enrichedById = new Map();
  const report = {
    local: 0,
    remote: 0,
    remote_cache: 0,
    skipped: 0,
    degraded: 0,
    local_errors: [],
    remote_errors: [],
  };
  const skipped = canonical.filter((record) => (record.routing?.requested_enrichment?.length ?? 0) === 0);
  const requested = canonical.filter((record) => !skipped.includes(record));
  const complex = requested.filter((record) => record.routing?.semantic_complexity === "complex");
  const localRecords = requested.filter((record) => record.routing?.semantic_complexity !== "complex");

  for (const record of skipped) {
    enrichedById.set(record.id, deterministicFallback(record, "not_requested"));
    report.skipped++;
  }

  for (const record of localRecords) {
    const result = await enrichSimple(record, local);
    enrichedById.set(record.id, result.enrichment);
    if (result.error) {
      report.degraded++;
      report.local_errors.push(`${record.id}: ${result.error}`);
    } else {
      report.local++;
    }
  }

  // One complex source per GLM request gives the card enough context and makes
  // malformed output degrade only that source, never an entire pair.
  for (const batch of makeBatches(complex, 1, policy.batch?.complex?.max_input_chars ?? 16000)) {
    const result = await cloud.completeJson({
      messages: [
        { role: "system", content: REMOTE_ENRICHMENT_SYSTEM_PROMPT },
        ...REMOTE_ENRICHMENT_FEW_SHOTS,
        { role: "user", content: remoteEnrichmentUserPrompt(batch) },
      ],
      validate: (value) => validateBatch(value, batch),
      repairMessages: (raw, errors) => [
        { role: "system", content: REMOTE_ENRICHMENT_SYSTEM_PROMPT },
        { role: "user", content: remoteRepairPrompt(raw, errors, batch) },
      ],
      maxTokens: policy.complex.max_output_tokens ?? 6000,
      force,
    });
    if (result.value) {
      for (const item of result.value.items) {
        const record = batch.find((candidate) => candidate.id === item.id);
        const metadata = {
          status: "complete", provider: "nvidia", model: result.model, cached: Boolean(result.cached),
        };
        const grounded = filterGroundedEnrichment(record, item, policy.thresholds, metadata);
        enrichedById.set(item.id, remoteEnrichmentPayload(record, item, grounded, metadata));
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

  const outputRecords = canonical.map((record) => ({
    ...record,
    enrichment: enrichedById.get(record.id) ?? deterministicFallback(record, "degraded"),
  }));
  writeJsonl(output, outputRecords);
  fs.writeFileSync(reportPath, `${JSON.stringify({
    input: path.relative(process.cwd(), input),
    output: path.relative(process.cwd(), output),
    ...report,
  }, null, 2)}\n`);
  console.log(`[enrich] complete: ${path.relative(process.cwd(), input)} -> ${path.relative(process.cwd(), output)} ${JSON.stringify(report)}`);
  return report;
}

async function enrichSimple(record, model) {
  try {
    const prompt = JSON.stringify({ id: record.id, kind: record.kind, title: record.title, content: record.content, facets: record.facets ?? {} }, null, 2);
    const result = await model.generateJson({ system: LOCAL_SIMPLE_ENRICHMENT_SYSTEM_PROMPT, user: prompt, maxNewTokens: policy.local.max_output_tokens ?? 700 });
    const parsed = result.parsed;
    if (!parsed || typeof parsed.summary !== "string" || typeof parsed.abstract !== "string") {
      return {
        enrichment: deterministicFallback(record, "degraded"),
        error: "model output did not contain valid summary and abstract fields",
      };
    }
    const entities = Array.isArray(parsed.entities) ? parsed.entities.filter((item) => item && evidenceExists(record, item.evidence)).map((item) => ({
      name: String(item.name ?? "").trim(), type: String(item.type ?? "other").trim(), confidence: 0.65, evidence: [String(item.evidence)],
    })).filter((item) => item.name) : [];
    return {
      enrichment: sanitize({
        schema_version: ENRICHMENT_VERSION, status: "complete", provider: "local-qwen", model: model.modelId,
        summary: String(parsed.summary).slice(0, 600), abstract: String(parsed.abstract).slice(0, 1600),
        card: fallbackCard(record, { title: record.title, purpose: String(parsed.summary), mechanism: String(parsed.abstract) }),
        tags: Array.isArray(parsed.tags) ? parsed.tags.map((tag) => normalizeWhitespace(tag)).filter(Boolean).slice(0, 16) : [],
        concepts: [], techniques: [], relations: [], mitre_candidates: [], entities,
      }),
      error: null,
    };
  } catch (error) {
    return {
      enrichment: deterministicFallback(record, "degraded"),
      error: normalizeWhitespace(error?.message ?? String(error)).slice(0, 500),
    };
  }
}

function deterministicFallback(record, status) {
  const summary = normalizeWhitespace(record.content).slice(0, 420);
  return sanitize({
    schema_version: ENRICHMENT_VERSION, status, provider: "deterministic", model: null,
    summary: summary || record.title, abstract: summary || record.title,
    card: fallbackCard(record, { title: record.title, purpose: summary || record.title, mechanism: summary || record.title }),
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
    if (!item?.card || typeof item.card !== "object") {
      errors.push(`${item?.id}.card must be object`);
    } else {
      for (const field of ["title", "purpose", "technical_context", "mechanism"]) {
        if (typeof item.card[field] !== "string") errors.push(`${item?.id}.card.${field} must be string`);
      }
      for (const field of ["components", "key_points", "artifacts", "tradecraft_context", "caveats"]) {
        if (!Array.isArray(item.card[field])) errors.push(`${item?.id}.card.${field} must be array`);
      }
    }
    for (const field of ["tags", "concepts", "techniques", "entities", "relations", "mitre_candidates"]) if (!Array.isArray(item?.[field])) errors.push(`${item?.id}.${field} must be array`);
  }
  for (const id of expected) if (!seen.has(id)) errors.push(`missing id ${id}`);
  return errors;
}

function remoteEnrichmentPayload(record, item, grounded, metadata) {
  return sanitize({
    schema_version: ENRICHMENT_VERSION,
    status: metadata.status,
    provider: metadata.provider,
    model: metadata.model,
    summary: grounded.summary,
    abstract: grounded.abstract,
    card: fallbackCard(record, item.card),
    ...grounded.enrichment,
  });
}

function fallbackCard(record, card = {}) {
  const text = normalizeWhitespace(record.content).slice(0, 600) || record.title;
  const strings = (value, limit) => Array.isArray(value) ? value.map((item) => String(item).trim()).filter(Boolean).slice(0, limit) : [];
  return {
    title: String(card.title ?? record.title).slice(0, 160),
    purpose: String(card.purpose ?? text).slice(0, 700),
    technical_context: String(card.technical_context ?? record.category ?? "").slice(0, 1200),
    mechanism: String(card.mechanism ?? text).slice(0, 1600),
    components: strings(card.components, 10),
    key_points: strings(card.key_points, 10),
    artifacts: strings(card.artifacts, 10),
    tradecraft_context: strings(card.tradecraft_context, 8),
    caveats: strings(card.caveats, 6),
  };
}
