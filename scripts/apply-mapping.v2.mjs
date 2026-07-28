#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { sanitize } from "./lib/sanitize.mjs";
import {
  CONTRACT_VERSION,
  readJsonl,
  readPath,
  sha256,
  stableCanonicalId,
  toStringArray,
  toText,
  validateCanonical,
  validateRouterMapping,
  writeJsonl,
} from "./lib/ingest-contract.mjs";

const inputArg = process.argv[2];
if (!inputArg) {
  console.error("Usage: node scripts/apply-mapping.v2.mjs <input.jsonl>");
  process.exit(1);
}

const input = path.resolve(inputArg);
const mappingPath = input.replace(/\.jsonl$/i, ".mapping.json");
const base = path.basename(input, ".jsonl");
const output = path.resolve("data/normalized", `${base}.jsonl`);
const reportPath = path.resolve("data/normalized", `${base}.report.json`);

if (!fs.existsSync(mappingPath)) throw new Error(`Mapping not found: ${mappingPath}`);
const mapping = JSON.parse(fs.readFileSync(mappingPath, "utf8"));
const mappingErrors = validateRouterMapping(mapping);
if (mappingErrors.length) throw new Error(`Invalid mapping: ${mappingErrors.join("; ")}`);

const { records, failures: parseFailures } = readJsonl(input);
const canonical = [];
const degraded = [];

for (const { index, value: rawRecord } of records) {
  const titleMapped = toText(readPath(rawRecord, mapping.field_map.title));
  const contentMapped = toText(readPath(rawRecord, mapping.field_map.content));
  const title = titleMapped || chooseTitle(rawRecord) || `${mapping.kind} record ${index + 1}`;
  const content = contentMapped || chooseContent(rawRecord) || JSON.stringify(rawRecord, null, 2);
  const explicitId = toText(readPath(rawRecord, mapping.field_map.id));
  const category = toText(readPath(rawRecord, mapping.field_map.category)) || mapping.constants.category || "uncategorized";
  const language = toText(readPath(rawRecord, mapping.field_map.language)) || mapping.detected_language || "unknown";
  const sourceName = toText(readPath(rawRecord, mapping.field_map.source)) || mapping.source_name;
  const tags = toStringArray(readPath(rawRecord, mapping.field_map.tags));
  const facets = resolveFacet(rawRecord, mapping.facets) ?? {};

  const record = sanitize({
    schema_version: CONTRACT_VERSION,
    id: stableCanonicalId({
      sourceFile: path.relative(process.cwd(), input),
      sourceName,
      explicitId,
      title,
      content,
    }),
    kind: mapping.kind,
    title,
    content,
    category,
    language,
    tags,
    publish_state: mapping.constants.publish_state,
    facets,
    source: {
      name: sourceName,
      input_file: path.relative(process.cwd(), input),
      record_index: index,
      record_sha256: sha256(JSON.stringify(rawRecord)),
      mapping_sha256: sha256(JSON.stringify(mapping)),
    },
    routing: {
      semantic_complexity: mapping.semantic_complexity,
      requested_enrichment: mapping.requested_enrichment,
      router_confidence: mapping.confidence,
    },
  });

  const errors = validateCanonical(record);
  if (errors.length) {
    degraded.push({ index, errors });
    continue;
  }
  canonical.push(record);
}

writeJsonl(output, canonical);
fs.writeFileSync(reportPath, `${JSON.stringify({
  input: path.relative(process.cwd(), input),
  output: path.relative(process.cwd(), output),
  total_lines: records.length + parseFailures.length,
  normalized: canonical.length,
  parse_failures: parseFailures,
  degraded_records: degraded,
  status: canonical.length > 0 ? "completed" : "completed_empty",
}, null, 2)}\n`);

console.log(`Normalized ${canonical.length}/${records.length + parseFailures.length} records -> ${output}`);
if (parseFailures.length || degraded.length) console.warn(`Non-blocking issues: ${parseFailures.length} parse failures, ${degraded.length} invalid canonical records`);

function chooseTitle(record) {
  return findByPreferredKeys(record, ["file_name", "title", "name", "question", "prompt", "scenario", "unit_id", "id"], 0, 4);
}

function chooseContent(record) {
  return findByPreferredKeys(record, ["content", "body", "text", "answer", "response", "completion", "output", "assessment", "description", "code", "markdown"], 0, 7);
}

function findByPreferredKeys(value, keys, depth, maxDepth) {
  if (!value || typeof value !== "object" || depth > maxDepth) return "";
  for (const key of keys) {
    if (Object.hasOwn(value, key)) {
      const text = toText(value[key]);
      if (text) return text;
    }
  }
  for (const child of Object.values(value)) {
    if (child && typeof child === "object") {
      const found = findByPreferredKeys(child, keys, depth + 1, maxDepth);
      if (found) return found;
    }
  }
  return "";
}

function resolveFacet(rawRecord, spec) {
  if (spec == null) return null;

  if (typeof spec === "object" && Array.isArray(spec.path)) {
    const val = readPath(rawRecord, spec);
    return sanitize(val);
  }

  if (Array.isArray(spec)) {
    const list = spec.map((item) => resolveFacet(rawRecord, item)).filter(Boolean);
    return list.length ? list : null;
  }

  if (typeof spec === "object") {
    const entries = Object.entries(spec)
      .map(([key, value]) => [key, resolveFacet(rawRecord, value)])
      .filter(([, value]) => value != null && (typeof value === "object" || toText(value)));
    return entries.length ? Object.fromEntries(entries) : null;
  }

  return sanitize(spec);
}
