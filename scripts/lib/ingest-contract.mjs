import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const CONTRACT_VERSION = "hugin.canonical.v2";
export const ROUTER_VERSION = "hugin.router.v2";
export const ENRICHMENT_VERSION = "hugin.enrichment.v2";

export const KINDS = Object.freeze([
  "source_code",
  "documentation",
  "training_qa",
  "writeup",
  "note",
  "playbook",
  "conversation",
  "unknown",
]);

export const COMPLEXITIES = Object.freeze(["simple", "general", "complex"]);
export const ENRICHMENT_TASKS = Object.freeze([
  "summary",
  "concepts",
  "techniques",
  "entities",
  "relations",
  "mitre_candidates",
  "tags",
]);

export function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

export function readJsonl(file) {
  const text = fs.readFileSync(file, "utf8");
  const records = [];
  const failures = [];
  for (const [index, rawLine] of text.split("\n").entries()) {
    const line = rawLine.trim();
    if (!line) continue;
    try {
      records.push({ index, value: JSON.parse(line) });
    } catch (error) {
      failures.push({ line: index + 1, reason: String(error?.message ?? error) });
    }
  }
  return { records, failures };
}

export function writeJsonl(file, records) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const body = records.map((record) => JSON.stringify(record)).join("\n");
  fs.writeFileSync(file, body ? `${body}\n` : "");
}

export function normalizeWhitespace(value) {
  const input = String(value ?? "");
  let output = "";
  let pendingSpace = false;
  for (const char of input) {
    const isSpace = char === " " || char === "\t" || char === "\n" || char === "\r" || char === "\f";
    if (isSpace) {
      pendingSpace = output.length > 0;
      continue;
    }
    if (pendingSpace) output += " ";
    pendingSpace = false;
    output += char;
  }
  return output.trim();
}

export function toText(value, joinWith = "\n") {
  if (value == null) return "";
  if (typeof value === "string") return value.trim();
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    return value.map((item) => toText(item, joinWith)).filter(Boolean).join(joinWith).trim();
  }
  return JSON.stringify(value, null, 2).trim();
}

export function toStringArray(value) {
  if (value == null) return [];
  const values = Array.isArray(value) ? value.flat(Infinity) : [value];
  return [...new Set(values.map((item) => normalizeWhitespace(toText(item))).filter(Boolean))];
}

export function isPathSpec(value) {
  if (value === null) return true;
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (!Array.isArray(value.path)) return false;
  if (!value.path.every((segment) => typeof segment === "string" || Number.isInteger(segment))) return false;
  if (value.join != null && typeof value.join !== "string") return false;
  return true;
}

function walkPath(currentValues, segment) {
  const next = [];
  for (const current of currentValues) {
    if (current == null) continue;
    if (segment === "*") {
      if (Array.isArray(current)) next.push(...current);
      else if (typeof current === "object") next.push(...Object.values(current));
      continue;
    }
    if (typeof segment === "number") {
      if (Array.isArray(current) && segment >= 0 && segment < current.length) next.push(current[segment]);
      continue;
    }
    if (typeof current === "object" && Object.hasOwn(current, segment)) next.push(current[segment]);
  }
  return next;
}

export function readPath(root, spec) {
  if (spec == null) return undefined;
  if (!isPathSpec(spec)) return undefined;
  let values = [root];
  for (const segment of spec.path) values = walkPath(values, segment);
  if (values.length === 0) return undefined;
  if (values.length === 1) return values[0];
  return spec.join != null ? values.map((item) => toText(item)).filter(Boolean).join(spec.join) : values;
}

function collectShape(value, prefix, out, depth = 0) {
  if (depth > 5) return;
  const type = Array.isArray(value) ? "array" : value === null ? "null" : typeof value;
  out.set(prefix || "$", type);
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 3)) collectShape(item, [...prefix, "*"], out, depth + 1);
  } else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value).slice(0, 40)) {
      collectShape(child, [...prefix, key], out, depth + 1);
    }
  }
}

export function buildStructuralProfile(records) {
  const shapeCounts = new Map();
  const pathTypes = new Map();
  const lengths = [];

  for (const record of records) {
    const shape = new Map();
    collectShape(record, [], shape);
    const signature = JSON.stringify([...shape.entries()].sort(([a], [b]) => String(a).localeCompare(String(b))));
    shapeCounts.set(signature, (shapeCounts.get(signature) ?? 0) + 1);
    lengths.push(JSON.stringify(record).length);
    for (const [pathSegments, type] of shape) {
      const key = JSON.stringify(pathSegments);
      if (!pathTypes.has(key)) pathTypes.set(key, new Set());
      pathTypes.get(key).add(type);
    }
  }

  const representativeIndexes = new Set();
  if (records.length > 0) {
    representativeIndexes.add(0);
    representativeIndexes.add(records.length - 1);
    representativeIndexes.add(Math.floor(records.length / 2));
    representativeIndexes.add(Math.floor(records.length / 4));
    representativeIndexes.add(Math.floor((records.length * 3) / 4));
  }

  const indexedLengths = lengths.map((length, index) => ({ length, index })).sort((a, b) => a.length - b.length);
  if (indexedLengths.length) {
    representativeIndexes.add(indexedLengths[0].index);
    representativeIndexes.add(indexedLengths.at(-1).index);
  }

  const examples = [...representativeIndexes]
    .filter((index) => index >= 0 && index < records.length)
    .slice(0, 8)
    .map((index) => ({ index, record: previewValue(records[index]) }));

  return {
    record_count: records.length,
    distinct_shapes: shapeCounts.size,
    average_serialized_chars: lengths.length
      ? Math.round(lengths.reduce((sum, value) => sum + value, 0) / lengths.length)
      : 0,
    paths: [...pathTypes.entries()].slice(0, 120).map(([serializedPath, types]) => ({
      path: JSON.parse(serializedPath),
      types: [...types],
    })),
    examples,
  };
}

export function previewValue(value, maxString = 320, depth = 0) {
  if (depth > 5) return "[depth-limit]";
  if (typeof value === "string") return value.length > maxString ? `${value.slice(0, maxString)}…` : value;
  if (Array.isArray(value)) return value.slice(0, 4).map((item) => previewValue(item, maxString, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).slice(0, 30).map(([key, child]) => [key, previewValue(child, maxString, depth + 1)]));
  }
  return value;
}

export function validateRouterMapping(mapping) {
  const errors = [];
  if (!mapping || typeof mapping !== "object" || Array.isArray(mapping)) return ["mapping must be an object"];
  if (mapping.schema_version !== ROUTER_VERSION) errors.push(`schema_version must be ${ROUTER_VERSION}`);
  if (typeof mapping.source_name !== "string" || !mapping.source_name.trim()) errors.push("source_name is required");
  if (!KINDS.includes(mapping.kind)) errors.push(`kind must be one of: ${KINDS.join(", ")}`);
  if (!COMPLEXITIES.includes(mapping.semantic_complexity)) errors.push("semantic_complexity is invalid");
  if (typeof mapping.confidence !== "number" || mapping.confidence < 0 || mapping.confidence > 1) errors.push("confidence must be 0..1");
  if (!mapping.field_map || typeof mapping.field_map !== "object") errors.push("field_map is required");
  for (const field of ["id", "title", "content", "category", "tags", "language", "source"]) {
    if (!isPathSpec(mapping.field_map?.[field] ?? null)) errors.push(`field_map.${field} must be null or a path spec`);
  }
  if (mapping.field_map?.content == null) errors.push("field_map.content is required");
  if (!Array.isArray(mapping.requested_enrichment)) errors.push("requested_enrichment must be an array");
  else if (mapping.requested_enrichment.some((task) => !ENRICHMENT_TASKS.includes(task))) errors.push("requested_enrichment contains an unsupported task");
  if (mapping.facets != null && (typeof mapping.facets !== "object" || Array.isArray(mapping.facets))) errors.push("facets must be an object");
  for (const [name, spec] of Object.entries(mapping.facets ?? {})) {
    if (!isPathSpec(spec)) errors.push(`facets.${name} must be null or a path spec`);
  }
  return errors;
}

export function validateCanonical(record) {
  const errors = [];
  if (record?.schema_version !== CONTRACT_VERSION) errors.push(`schema_version must be ${CONTRACT_VERSION}`);
  if (typeof record?.id !== "string" || !record.id) errors.push("id is required");
  if (!KINDS.includes(record?.kind)) errors.push("kind is invalid");
  if (typeof record?.title !== "string" || !record.title.trim()) errors.push("title is required");
  if (typeof record?.content !== "string" || !record.content.trim()) errors.push("content is required");
  if (!COMPLEXITIES.includes(record?.routing?.semantic_complexity)) errors.push("routing.semantic_complexity is invalid");
  return errors;
}

export function stableCanonicalId({ sourceFile, sourceName, explicitId, title, content }) {
  const identity = explicitId
    ? `${sourceName}:${explicitId}`
    : `${sourceName}:${title}:${sha256(content).slice(0, 24)}`;
  return `ingest:${sha256(`${sourceFile}:${identity}`).slice(0, 28)}`;
}

export function canonicalizeRecord(rawRecord, mapping, sourceName, index = 0, sourceFile = "test") {
  const titleMapped = toText(readPath(rawRecord, mapping.field_map?.title));
  const contentMapped = toText(readPath(rawRecord, mapping.field_map?.content));
  const title = titleMapped || rawRecord.file_name || rawRecord.title || rawRecord.prompt || rawRecord.question || rawRecord.scenario || rawRecord.headline || `${mapping.kind} record ${index + 1}`;
  const content = contentMapped || rawRecord.content || rawRecord.body || rawRecord.answer || rawRecord.details || JSON.stringify(rawRecord);
  const explicitId = toText(readPath(rawRecord, mapping.field_map?.id));
  const category = toText(readPath(rawRecord, mapping.field_map?.category)) || mapping.constants?.category || "uncategorized";
  const language = toText(readPath(rawRecord, mapping.field_map?.language)) || mapping.detected_language || "unknown";
  const tags = toStringArray(readPath(rawRecord, mapping.field_map?.tags));

  function resolveSpec(spec) {
    if (!spec) return null;
    if (typeof spec === "object" && Array.isArray(spec.path)) return readPath(rawRecord, spec);
    if (typeof spec === "object") {
      const obj = {};
      for (const [k, v] of Object.entries(spec)) {
        const res = resolveSpec(v);
        if (res != null) obj[k] = res;
      }
      return Object.keys(obj).length ? obj : null;
    }
    return spec;
  }

  const facets = resolveSpec(mapping.facets) ?? {};

  return {
    schema_version: CONTRACT_VERSION,
    id: stableCanonicalId({ sourceFile, sourceName, explicitId, title, content }),
    kind: mapping.kind,
    title,
    content,
    category,
    language,
    tags,
    publish_state: mapping.constants?.publish_state ?? "core",
    facets,
    source: {
      name: sourceName,
      input_file: sourceFile,
      record_index: index,
      record_sha256: sha256(JSON.stringify(rawRecord)),
      mapping_sha256: sha256(JSON.stringify(mapping)),
    },
    routing: {
      semantic_complexity: mapping.semantic_complexity ?? "general",
      requested_enrichment: mapping.requested_enrichment ?? ["summary"],
      router_confidence: mapping.confidence ?? 1.0,
    },
  };
}

export function evidenceExists(record, evidence) {
  const needle = String(evidence ?? "").trim();
  if (!needle) return false;
  const haystacks = [record.title, record.content, JSON.stringify(record.facets ?? {})].filter(Boolean);
  if (haystacks.some((text) => String(text).includes(needle))) return true;
  const normalizedNeedle = normalizeWhitespace(needle);
  return normalizedNeedle.length >= 8 && haystacks.some((text) => normalizeWhitespace(text).includes(normalizedNeedle));
}

export function filterGroundedEnrichment(record, item, thresholds, metadata) {
  const grounded = (items, threshold) => (Array.isArray(items) ? items : []).filter((candidate) => {
    if (typeof candidate?.confidence !== "number" || candidate.confidence < threshold) return false;
    if (!Array.isArray(candidate.evidence) || candidate.evidence.length === 0) return false;
    return candidate.evidence.every((quote) => evidenceExists(record, quote));
  });

  return {
    id: record.id,
    kind: record.kind,
    title: record.title,
    content: record.content,
    category: record.category,
    language: record.language,
    tags: record.tags,
    publish_state: record.publish_state,
    facets: record.facets,
    summary: item?.summary ?? "",
    abstract: item?.abstract ?? "",
    enrichment: {
      concepts: grounded(item?.concepts, thresholds.claim ?? 0.68),
      techniques: grounded(item?.techniques, thresholds.technique ?? 0.76),
      entities: grounded(item?.entities, thresholds.entity ?? 0.64),
      relations: grounded(item?.relations, thresholds.relation ?? 0.76),
      mitre_candidates: grounded(item?.mitre_candidates, thresholds.mitre ?? 0.86),
      tags: Array.isArray(item?.tags) ? item.tags.slice(0, 12) : [],
    },
    provenance: {
      source: record.source,
      enrichment: metadata,
    },
  };
}

export const ROUTER_JSON_SCHEMA = {
  name: "hugin_router_mapping",
  strict: true,
  schema: {
    type: "object",
    additionalProperties: false,
    required: ["schema_version", "source_name", "kind", "record_shape", "detected_language", "semantic_complexity", "confidence", "field_map", "constants", "facets", "requested_enrichment", "notes"],
    properties: {
      schema_version: { const: ROUTER_VERSION },
      source_name: { type: "string", minLength: 1 },
      kind: { enum: KINDS },
      record_shape: { enum: ["flat", "nested", "mixed", "raw_text"] },
      detected_language: { type: "string" },
      semantic_complexity: { enum: COMPLEXITIES },
      confidence: { type: "number", minimum: 0, maximum: 1 },
      field_map: {
        type: "object",
        additionalProperties: false,
        required: ["id", "title", "content", "category", "tags", "language", "source"],
        properties: Object.fromEntries(["id", "title", "content", "category", "tags", "language", "source"].map((name) => [name, {
          anyOf: [
            { type: "null" },
            {
              type: "object",
              additionalProperties: false,
              required: ["path", "join"],
              properties: {
                path: { type: "array", items: { anyOf: [{ type: "string" }, { type: "integer", minimum: 0 }] } },
                join: { anyOf: [{ type: "string" }, { type: "null" }] },
              },
            },
          ],
        }]))
      },
      constants: {
        type: "object",
        additionalProperties: false,
        required: ["category", "publish_state"],
        properties: {
          category: { anyOf: [{ type: "string" }, { type: "null" }] },
          publish_state: { enum: ["core", "support"] },
        },
      },
      facets: {
        type: "object",
        additionalProperties: {
          anyOf: [
            { type: "null" },
            {
              type: "object",
              additionalProperties: false,
              required: ["path", "join"],
              properties: {
                path: { type: "array", items: { anyOf: [{ type: "string" }, { type: "integer", minimum: 0 }] } },
                join: { anyOf: [{ type: "string" }, { type: "null" }] },
              },
            },
          ],
        },
      },
      requested_enrichment: { type: "array", uniqueItems: true, items: { enum: ENRICHMENT_TASKS } },
      notes: { type: "string" },
    },
  },
};

const evidenceArray = { type: "array", minItems: 1, maxItems: 4, items: { type: "string", minLength: 4 } };
const confidence = { type: "number", minimum: 0, maximum: 1 };

export const ENRICHMENT_JSON_SCHEMA = {
  name: "hugin_semantic_enrichment_batch",
  strict: true,
  schema: {
    type: "object",
    additionalProperties: false,
    required: ["items"],
    properties: {
      items: {
        type: "array",
        items: {
          type: "object",
          additionalProperties: false,
          required: ["id", "summary", "abstract", "tags", "concepts", "techniques", "entities", "relations", "mitre_candidates"],
          properties: {
            id: { type: "string" },
            summary: { type: "string", maxLength: 600 },
            abstract: { type: "string", maxLength: 1600 },
            tags: { type: "array", maxItems: 16, items: { type: "string", minLength: 1, maxLength: 80 } },
            concepts: {
              type: "array", maxItems: 12, items: {
                type: "object", additionalProperties: false,
                required: ["name", "type", "description", "confidence", "evidence"],
                properties: {
                  name: { type: "string", minLength: 2, maxLength: 120 },
                  type: { enum: ["mechanism", "primitive", "architecture", "procedure", "defensive_concept", "offensive_concept", "general_concept"] },
                  description: { type: "string", maxLength: 500 }, confidence, evidence: evidenceArray,
                },
              },
            },
            techniques: {
              type: "array", maxItems: 10, items: {
                type: "object", additionalProperties: false,
                required: ["name", "description", "phase", "confidence", "evidence"],
                properties: {
                  name: { type: "string", minLength: 2, maxLength: 140 },
                  description: { type: "string", maxLength: 600 },
                  phase: { enum: ["recon", "initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion", "credential_access", "discovery", "lateral_movement", "collection", "c2", "exfiltration", "impact", "development", "unknown"] },
                  confidence, evidence: evidenceArray,
                },
              },
            },
            entities: {
              type: "array", maxItems: 16, items: {
                type: "object", additionalProperties: false,
                required: ["name", "type", "confidence", "evidence"],
                properties: {
                  name: { type: "string", minLength: 2, maxLength: 140 },
                  type: { enum: ["tool", "api", "function", "file", "protocol", "platform", "vulnerability", "library", "product", "actor", "other"] },
                  confidence, evidence: evidenceArray,
                },
              },
            },
            relations: {
              type: "array", maxItems: 16, items: {
                type: "object", additionalProperties: false,
                required: ["source", "target", "type", "description", "confidence", "evidence"],
                properties: {
                  source: { type: "string", minLength: 2, maxLength: 140 },
                  target: { type: "string", minLength: 2, maxLength: 140 },
                  type: { enum: ["implements", "uses", "depends_on", "enables", "mitigates", "detects", "bypasses", "documents", "related_to"] },
                  description: { type: "string", maxLength: 500 }, confidence, evidence: evidenceArray,
                },
              },
            },
            mitre_candidates: {
              type: "array", maxItems: 8, items: {
                type: "object", additionalProperties: false,
                required: ["id", "confidence", "evidence"],
                properties: { id: { type: "string", minLength: 5, maxLength: 12 }, confidence, evidence: evidenceArray },
              },
            },
          },
        },
      },
    },
  },
};
