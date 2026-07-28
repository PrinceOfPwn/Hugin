#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import {
  buildStructuralProfile,
  ROUTER_VERSION,
  sha256,
  validateRouterMapping,
} from "./lib/ingest-contract.mjs";
import { LocalTextModel } from "./lib/local-model.mjs";
import {
  ROUTER_SYSTEM_PROMPT,
  routerRepairPrompt,
  routerUserPrompt,
} from "./lib/prompts.mjs";

const argv = process.argv.slice(2);
const inputArg = argv.find((arg) => !arg.startsWith("--"));
const force = argv.includes("--force");
if (!inputArg) {
  console.error("Usage: node scripts/detect-format.v2.mjs <input.jsonl> [--force]");
  process.exit(1);
}

const input = path.resolve(inputArg);
const mappingPath = input.replace(/\.jsonl$/i, ".mapping.json");
const modelId = process.env.HUGIN_DETECT_MODEL ?? "onnx-community/gemma-4-E2B-it-ONNX";
const cacheDir = process.env.HUGIN_MODEL_CACHE ?? ".hf-cache";

if (!fs.existsSync(input)) throw new Error(`Input not found: ${input}`);
const raw = fs.readFileSync(input, "utf8");
const inputHash = sha256(raw);

if (!force && fs.existsSync(mappingPath)) {
  try {
    const current = JSON.parse(fs.readFileSync(mappingPath, "utf8"));
    if (current?._detected?.input_sha256 === inputHash && current?._detected?.router_version === ROUTER_VERSION && current?._detected?.model === modelId) {
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

const firstRecord = parsedRecords[0] ?? {};
const isSourceCode = Boolean(
  (firstRecord.file_name && (firstRecord.content || firstRecord.code)) ||
  (firstRecord.file_type && (firstRecord.content || firstRecord.code)) ||
  (firstRecord.relative_path && (firstRecord.content || firstRecord.code))
);

const isQa = Boolean(
  (firstRecord.prompt || firstRecord.question) && (firstRecord.answer || firstRecord.response || firstRecord.completion)
);

const isDoc = Boolean(
  firstRecord.title && (firstRecord.body || firstRecord.content || firstRecord.text)
);

const profile = buildStructuralProfile(parsedRecords);
const local = new LocalTextModel({ modelId, cacheDir, maxNewTokens: 1000 });
let output;
let rawOutput = "";

if (isSourceCode) {
  output = deterministicCodeMapping(parsedRecords, path.basename(input, ".jsonl"));
} else if (isQa) {
  output = deterministicQaMapping(parsedRecords, path.basename(input, ".jsonl"));
} else if (isDoc) {
  output = deterministicDocMapping(parsedRecords, path.basename(input, ".jsonl"));
} else {
  try {
    const first = await local.generateJson({
      system: ROUTER_SYSTEM_PROMPT,
      user: routerUserPrompt(profile),
      maxNewTokens: 1000,
    });
    output = first.parsed;
    rawOutput = first.raw;
    let errors = validateRouterMapping(output);

    if (errors.length > 0) {
      const repaired = await local.generateJson({
        system: ROUTER_SYSTEM_PROMPT,
        user: routerRepairPrompt(rawOutput, errors, profile),
        maxNewTokens: 1000,
      });
      output = repaired.parsed;
      rawOutput = repaired.raw;
      errors = validateRouterMapping(output);
    }

    if (errors.length > 0) {
      console.warn(`Local router remained invalid; using deterministic fallback: ${errors.join("; ")}`);
      output = deterministicFallback(parsedRecords, path.basename(input, ".jsonl"));
    }
  } finally {
    await local.dispose();
  }
}

if (output.kind === "dataset_record") output.kind = "unknown";

output._detected = {
  input: path.relative(process.cwd(), input),
  input_records: parsedRecords.length,
  input_sha256: inputHash,
  router_version: ROUTER_VERSION,
  model: modelId,
  detected_at: new Date().toISOString(),
};

fs.writeFileSync(mappingPath, `${JSON.stringify(output, null, 2)}\n`);
console.log(`Mapping written: ${mappingPath}`);
console.log(`  kind: ${output.kind}`);
console.log(`  complexity: ${output.semantic_complexity}`);
console.log(`  confidence: ${output.confidence}`);

function pathForKey(record, candidates) {
  for (const key of candidates) if (Object.hasOwn(record, key)) return { path: [key], join: null };
  return null;
}

function deterministicCodeMapping(records, sourceName) {
  const first = records[0] ?? {};
  return {
    schema_version: ROUTER_VERSION,
    source_name: sourceName,
    kind: "source_code",
    record_shape: "mixed",
    detected_language: first.file_type ?? "raw_code",
    semantic_complexity: "complex",
    confidence: 1.0,
    field_map: {
      id: pathForKey(first, ["id", "unit_id", "uuid"]),
      title: pathForKey(first, ["file_name", "relative_path", "title", "id"]) ?? { path: ["file_name"], join: null },
      content: pathForKey(first, ["content", "code", "body", "text"]) ?? { path: ["content"], join: null },
      category: pathForKey(first, ["category", "task_type", "topic"]),
      tags: pathForKey(first, ["tags", "labels"]),
      language: pathForKey(first, ["file_type", "language", "lang"]),
      source: pathForKey(first, ["source", "source_name", "origin"])
    },
    constants: { category: null, publish_state: "core" },
    facets: {
      code: {
        file_name: pathForKey(first, ["file_name"]),
        relative_path: pathForKey(first, ["relative_path"]),
        language: pathForKey(first, ["file_type", "language"])
      }
    },
    requested_enrichment: ["summary", "concepts", "techniques", "entities", "relations", "mitre_candidates", "tags"],
    notes: "Automatic deterministic code mapping"
  };
}

function deterministicQaMapping(records, sourceName) {
  const first = records[0] ?? {};
  return {
    schema_version: ROUTER_VERSION,
    source_name: sourceName,
    kind: "training_qa",
    record_shape: "mixed",
    detected_language: "en",
    semantic_complexity: "general",
    confidence: 1.0,
    field_map: {
      id: pathForKey(first, ["id", "unit_id", "uuid"]),
      title: pathForKey(first, ["prompt", "question", "scenario", "id"]) ?? { path: ["prompt"], join: null },
      content: pathForKey(first, ["answer", "response", "completion", "output"]) ?? { path: ["answer"], join: null },
      category: pathForKey(first, ["category", "task_type", "topic"]),
      tags: pathForKey(first, ["tags", "labels"]),
      language: pathForKey(first, ["language", "lang"]),
      source: pathForKey(first, ["source", "source_name", "origin"])
    },
    constants: { category: null, publish_state: "core" },
    facets: {
      qa: {
        prompt: pathForKey(first, ["prompt", "question"]),
        answer: pathForKey(first, ["answer", "response"])
      }
    },
    requested_enrichment: ["summary", "concepts", "techniques", "entities", "relations", "mitre_candidates", "tags"],
    notes: "Automatic deterministic QA mapping"
  };
}

function deterministicDocMapping(records, sourceName) {
  const first = records[0] ?? {};
  return {
    schema_version: ROUTER_VERSION,
    source_name: sourceName,
    kind: "documentation",
    record_shape: "mixed",
    detected_language: "en",
    semantic_complexity: "general",
    confidence: 1.0,
    field_map: {
      id: pathForKey(first, ["id", "unit_id", "uuid"]),
      title: pathForKey(first, ["title", "name", "headline"]) ?? { path: ["title"], join: null },
      content: pathForKey(first, ["body", "content", "text", "details"]) ?? { path: ["body"], join: null },
      category: pathForKey(first, ["category", "task_type", "topic"]),
      tags: pathForKey(first, ["tags", "labels"]),
      language: pathForKey(first, ["language", "lang"]),
      source: pathForKey(first, ["source", "source_name", "origin"])
    },
    constants: { category: null, publish_state: "core" },
    requested_enrichment: ["summary", "concepts", "techniques", "entities", "relations", "mitre_candidates", "tags"],
    notes: "Automatic deterministic documentation mapping"
  };
}

function deterministicFallback(records, sourceName) {
  const first = records[0] ?? {};
  const title = pathForKey(first, ["file_name", "title", "name", "question", "prompt", "scenario", "unit_id", "id"]);
  const content = pathForKey(first, ["content", "body", "text", "answer", "response", "completion", "output", "assessment", "description", "code"])
    ?? { path: [], join: null };
  let kind = "unknown";
  if (Object.hasOwn(first, "file_name") && Object.hasOwn(first, "content")) kind = "source_code";
  else if ((Object.hasOwn(first, "prompt") || Object.hasOwn(first, "question")) && (Object.hasOwn(first, "answer") || Object.hasOwn(first, "response"))) kind = "training_qa";
  else if (Object.hasOwn(first, "title") && (Object.hasOwn(first, "body") || Object.hasOwn(first, "content"))) kind = "documentation";

  return {
    schema_version: ROUTER_VERSION,
    source_name: sourceName,
    kind,
    record_shape: "mixed",
    detected_language: "unknown",
    semantic_complexity: kind === "source_code" ? "complex" : "general",
    confidence: 0.35,
    field_map: {
      id: pathForKey(first, ["id", "unit_id", "uuid"]),
      title,
      content,
      category: pathForKey(first, ["category", "task_type", "topic"]),
      tags: pathForKey(first, ["tags", "labels"]),
      language: pathForKey(first, ["language", "file_type", "lang"]),
    },
    requested_enrichment: ["summary", "concepts", "techniques", "entities", "relations", "mitre_candidates", "tags"],
    notes: "Automatic fallback mapping generated after local router validation failure.",
  };
}
