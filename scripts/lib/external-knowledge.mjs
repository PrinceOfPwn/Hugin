import crypto from "node:crypto";

export const EXTERNAL_KNOWLEDGE_VERSION = "hugin.external-knowledge.v1";
export const DEFAULT_CHUNK_CHARS = 48000;
export const DEFAULT_BATCH_CHARS = 220000;
export const MAX_EVIDENCE_CHARS = 220;

export const sha256 = (value) => crypto.createHash("sha256").update(String(value)).digest("hex");

export function stableStringify(value) {
  const normalize = (item, inArray = false) => {
    if (item === null || typeof item === "string" || typeof item === "boolean" || typeof item === "number") return item;
    if (Array.isArray(item)) return item.map((child) => normalize(child, true) ?? null);
    if (item && typeof item === "object") {
      return Object.fromEntries(
        Object.keys(item).sort().flatMap((key) => {
          const child = normalize(item[key], false);
          return child === undefined ? [] : [[key, child]];
        }),
      );
    }
    return inArray ? null : undefined;
  };
  return JSON.stringify(normalize(value));
}

export function slugify(value, fallback = "source") {
  const slug = String(value ?? "")
    .normalize("NFKD")
    .toLowerCase()
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 96);
  return slug || fallback;
}

export function compactText(value) {
  return String(value ?? "")
    .replace(/\r\n/g, "\n")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function decodeCodePoint(raw, radix, whole) {
  const value = Number.parseInt(raw, radix);
  if (!Number.isInteger(value) || value < 0 || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return whole;
  try { return String.fromCodePoint(value); } catch { return whole; }
}

export function decodeHtmlEntities(value) {
  const named = {
    amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ",
    ndash: "–", mdash: "—", hellip: "…",
  };
  return String(value ?? "")
    .replace(/&#(\d+);/g, (whole, n) => decodeCodePoint(n, 10, whole))
    .replace(/&#x([0-9a-f]+);/gi, (whole, n) => decodeCodePoint(n, 16, whole))
    .replace(/&([a-z]+);/gi, (whole, name) => named[name.toLowerCase()] ?? whole);
}

export function htmlToText(html) {
  const titleMatch = String(html).match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = compactText(decodeHtmlEntities(titleMatch?.[1]?.replace(/<[^>]+>/g, " ") ?? ""));
  const withoutNoise = String(html)
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<(script|style|svg|noscript|template|iframe)[^>]*>[\s\S]*?<\/\1>/gi, " ")
    .replace(/<(br|\/p|\/div|\/li|\/h[1-6]|\/section|\/article|\/tr)>/gi, "\n")
    .replace(/<[^>]+>/g, " ");
  return { title, text: compactText(decodeHtmlEntities(withoutNoise)) };
}

function splitBoundedText(text, maxChars) {
  if (!Number.isInteger(maxChars) || maxChars < 1) throw new RangeError("maxChars must be a positive integer");
  const clean = compactText(text);
  if (!clean) return [];
  const slices = [];
  let start = 0;
  while (start < clean.length) {
    let end = Math.min(clean.length, start + maxChars);
    if (end < clean.length) {
      const paragraph = clean.lastIndexOf("\n\n", end);
      const sentence = clean.lastIndexOf(". ", end);
      const whitespace = clean.lastIndexOf(" ", end);
      const candidate = Math.max(paragraph, sentence, whitespace);
      if (candidate > start + Math.floor(maxChars * 0.6)) end = candidate + (candidate === sentence ? 1 : 0);
    }
    if (end <= start) end = Math.min(clean.length, start + maxChars);
    slices.push(clean.slice(start, end).trim());
    start = end;
  }
  return slices.filter(Boolean);
}

export function chunkPdfText(text, { chunkChars = DEFAULT_CHUNK_CHARS, overlapPages = 1, maxPages = Infinity } = {}) {
  if (!Number.isInteger(chunkChars) || chunkChars < 1) throw new RangeError("chunkChars must be a positive integer");
  const rawPages = String(text ?? "").split("\f");
  const pageSegments = rawPages
    .slice(0, Number.isFinite(maxPages) ? Math.max(0, maxPages) : undefined)
    .flatMap((page, index) => splitBoundedText(page, chunkChars).map((segment, segmentIndex) => ({
      page: index + 1,
      segment: segmentIndex,
      text: segment,
    })))
    .filter((page) => page.text);
  if (!pageSegments.length) return [];

  const chunks = [];
  let cursor = 0;
  while (cursor < pageSegments.length) {
    const start = cursor;
    let end = cursor;
    let chars = 0;
    while (end < pageSegments.length) {
      const next = pageSegments[end].text.length + (end > start ? 2 : 0);
      if (end > start && chars + next > chunkChars) break;
      chars += next;
      end++;
    }
    if (end === start) end++;
    const selected = pageSegments.slice(start, end);
    chunks.push({
      page_start: selected[0].page,
      page_end: selected.at(-1).page,
      text: selected.map((page) => page.text).join("\n\n"),
    });
    if (end >= pageSegments.length) break;

    const overlapFloor = selected.at(-1).page - Math.max(0, overlapPages) + 1;
    let overlapIndex = end;
    while (overlapIndex > start && pageSegments[overlapIndex - 1].page >= overlapFloor) overlapIndex--;
    cursor = Math.max(start + 1, overlapIndex);
  }
  return chunks;
}

export function chunkPlainText(text, { chunkChars = DEFAULT_CHUNK_CHARS, overlapChars = 1600 } = {}) {
  if (!Number.isInteger(chunkChars) || chunkChars < 1) throw new RangeError("chunkChars must be a positive integer");
  const clean = compactText(text);
  if (!clean) return [];
  const chunks = [];
  let start = 0;
  while (start < clean.length) {
    let end = Math.min(clean.length, start + chunkChars);
    if (end < clean.length) {
      const boundary = clean.lastIndexOf("\n\n", end);
      const sentence = clean.lastIndexOf(". ", end);
      const candidate = Math.max(boundary, sentence);
      if (candidate > start + Math.floor(chunkChars * 0.65)) end = candidate + (candidate === sentence ? 1 : 0);
    }
    chunks.push({ char_start: start, char_end: end, text: clean.slice(start, end).trim() });
    if (end >= clean.length) break;
    start = Math.max(start + 1, end - Math.max(0, overlapChars));
  }
  return chunks.filter((chunk) => chunk.text);
}

export function packByChars(items, maxChars = DEFAULT_BATCH_CHARS, maxItems = 8) {
  const batches = [];
  let current = [];
  let chars = 0;
  for (const item of items) {
    const size = JSON.stringify(item).length;
    if (current.length && (current.length >= maxItems || chars + size > maxChars)) {
      batches.push(current);
      current = [];
      chars = 0;
    }
    current.push(item);
    chars += size;
  }
  if (current.length) batches.push(current);
  return batches;
}

export function shortEvidence(value) {
  return compactText(value).slice(0, MAX_EVIDENCE_CHARS);
}

export function evidenceExistsInChunks(quote, chunkIds, chunksById) {
  const needle = compactText(quote);
  if (!needle || needle.length < 8 || needle.length > MAX_EVIDENCE_CHARS) return false;
  for (const id of chunkIds ?? []) {
    const chunk = chunksById.get(id);
    if (!chunk) continue;
    const haystack = compactText(chunk.body ?? chunk.text ?? "");
    if (haystack.includes(needle)) return true;
  }
  return false;
}

const STRING_ARRAY_FIELDS = [
  "prerequisites", "attack_surface", "validation_signals", "pivots", "failure_modes", "tags",
];

const asArray = (value) => Array.isArray(value) ? value : [];
const isString = (value) => typeof value === "string" && value.trim().length > 0;
const isOptionalString = (value) => value == null || typeof value === "string";
const isConfidence = (value) => typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;

function validateArrayMemberShapes(unit, where, errors) {
  for (const [index, step] of asArray(unit.operator_flow).entries()) {
    if (typeof step === "string") {
      if (!step.trim()) errors.push(`${where}.operator_flow[${index}] must not be empty`);
    } else if (!step || typeof step !== "object" || !isString(step.action) || !isOptionalString(step.why)) {
      errors.push(`${where}.operator_flow[${index}] must be a string or {action, why?}`);
    }
  }

  for (const [index, point] of asArray(unit.decision_points).entries()) {
    if (!point || typeof point !== "object" || !isString(point.condition) || !isString(point.action) || !isOptionalString(point.rationale)) {
      errors.push(`${where}.decision_points[${index}] must be {condition, action, rationale?}`);
    }
  }

  for (const [index, tool] of asArray(unit.tool_usage).entries()) {
    if (!tool || typeof tool !== "object" || !isString(tool.tool) || !isString(tool.use) || !isOptionalString(tool.pattern)) {
      errors.push(`${where}.tool_usage[${index}] must be {tool, use, pattern?}`);
    }
  }

  for (const [index, ref] of asArray(unit.source_refs).entries()) {
    if (!ref || typeof ref !== "object" || !isString(ref.url) || !Array.isArray(ref.chunk_ids) || !Array.isArray(ref.evidence)) {
      errors.push(`${where}.source_refs[${index}] must be an object with url, chunk_ids, and evidence`);
    }
  }

  for (const field of ["concepts", "techniques", "entities"]) {
    for (const [index, item] of asArray(unit[field]).entries()) {
      if (!item || typeof item !== "object" || !isString(item.name) || !Array.isArray(item.evidence) || (item.confidence != null && !isConfidence(item.confidence))) {
        errors.push(`${where}.${field}[${index}] must be an object with name, evidence, and optional confidence 0..1`);
      }
    }
  }

  for (const [index, relation] of asArray(unit.relations).entries()) {
    if (!relation || typeof relation !== "object" || !isString(relation.source) || !isString(relation.target) || !isString(relation.type) || !Array.isArray(relation.evidence) || (relation.confidence != null && !isConfidence(relation.confidence))) {
      errors.push(`${where}.relations[${index}] must be {source,target,type,evidence,confidence?}`);
    }
  }

  for (const [index, candidate] of asArray(unit.mitre_candidates).entries()) {
    if (!candidate || typeof candidate !== "object" || !isString(candidate.id) || !Array.isArray(candidate.evidence) || (candidate.confidence != null && !isConfidence(candidate.confidence))) {
      errors.push(`${where}.mitre_candidates[${index}] must be {id,evidence,confidence?}`);
    }
  }
}

function sourceRefMetadata(ref, chunksById) {
  const ids = Array.isArray(ref?.chunk_ids) ? ref.chunk_ids : [];
  if (!ids.length) return null;
  const chunks = ids.map((id) => chunksById.get(id));
  if (chunks.some((chunk) => !chunk)) return null;
  const first = chunks[0].source_document ?? {};
  const sourceIds = new Set(chunks.map((chunk) => chunk.source_document?.source_id));
  if (sourceIds.size !== 1 || !first.source_id) return null;
  const pageStarts = chunks.map((chunk) => chunk.source_document?.page_start).filter(Number.isFinite);
  const pageEnds = chunks.map((chunk) => chunk.source_document?.page_end).filter(Number.isFinite);
  return {
    source_id: first.source_id,
    title: first.source_title,
    url: first.source_url,
    source_sha256: first.source_sha256,
    page_start: pageStarts.length ? Math.min(...pageStarts) : null,
    page_end: pageEnds.length ? Math.max(...pageEnds) : null,
  };
}

export function validateKnowledgeUnits(value, { root = "units", chunksById = null } = {}) {
  const errors = [];
  if (!value || typeof value !== "object" || !Array.isArray(value[root])) return [`${root} array is required`];
  const keys = new Set();
  for (const [index, unit] of value[root].entries()) {
    const where = `${root}[${index}]`;
    if (!unit || typeof unit !== "object" || Array.isArray(unit)) {
      errors.push(`${where} must be an object`);
      continue;
    }
    for (const field of ["unit_key", "title", "knowledge_type", "summary", "objective", "applicability"]) {
      if (!isString(unit?.[field])) errors.push(`${where}.${field} must be a non-empty string`);
    }
    if (unit?.unit_key) {
      if (keys.has(unit.unit_key)) errors.push(`${where}.unit_key must be unique`);
      keys.add(unit.unit_key);
    }
    for (const field of STRING_ARRAY_FIELDS) {
      if (!Array.isArray(unit?.[field])) errors.push(`${where}.${field} must be an array`);
      else if (unit[field].some((item) => !isString(item))) errors.push(`${where}.${field} must contain only non-empty strings`);
    }
    for (const field of ["operator_flow", "decision_points", "tool_usage", "source_refs", "concepts", "techniques", "entities", "relations", "mitre_candidates"]) {
      if (!Array.isArray(unit?.[field])) errors.push(`${where}.${field} must be an array`);
    }
    if (!Array.isArray(unit?.source_refs) || unit.source_refs.length === 0) errors.push(`${where}.source_refs must contain grounded provenance`);
    validateArrayMemberShapes(unit, where, errors);

    const localNames = new Set([
      ...asArray(unit?.concepts).map((item) => item?.name),
      ...asArray(unit?.techniques).map((item) => item?.name),
      ...asArray(unit?.entities).map((item) => item?.name),
    ].filter(Boolean));
    for (const [relationIndex, relation] of asArray(unit?.relations).entries()) {
      if (!localNames.has(relation?.source) || !localNames.has(relation?.target)) {
        errors.push(`${where}.relations[${relationIndex}] endpoints must reuse names from the same unit`);
      }
    }

    if (chunksById) {
      const sourceRefs = asArray(unit?.source_refs);
      const unitChunkIds = [...new Set(sourceRefs.flatMap((ref) => Array.isArray(ref?.chunk_ids) ? ref.chunk_ids : []))];
      for (const [refIndex, ref] of sourceRefs.entries()) {
        const refWhere = `${where}.source_refs[${refIndex}]`;
        if (typeof ref?.url !== "string" || !/^https?:\/\//i.test(ref.url)) errors.push(`${refWhere}.url must be http(s)`);
        if (!Array.isArray(ref?.chunk_ids) || !ref.chunk_ids.length) errors.push(`${refWhere}.chunk_ids is required`);
        if (!Array.isArray(ref?.evidence) || !ref.evidence.length) errors.push(`${refWhere}.evidence is required`);

        const metadata = sourceRefMetadata(ref, chunksById);
        if (!metadata) {
          errors.push(`${refWhere}.chunk_ids must all resolve to exactly one source document`);
        } else {
          if (ref.url !== metadata.url) errors.push(`${refWhere}.url must match referenced chunk provenance`);
          if (ref.page_start != null && metadata.page_start != null && Number(ref.page_start) !== metadata.page_start) errors.push(`${refWhere}.page_start must match referenced chunks`);
          if (ref.page_end != null && metadata.page_end != null && Number(ref.page_end) !== metadata.page_end) errors.push(`${refWhere}.page_end must match referenced chunks`);
        }
        for (const quote of asArray(ref?.evidence)) {
          if (!evidenceExistsInChunks(quote, asArray(ref?.chunk_ids), chunksById)) errors.push(`${refWhere}.evidence is not an exact short quote from referenced chunks`);
        }
      }

      for (const field of ["concepts", "techniques", "entities", "relations", "mitre_candidates"]) {
        for (const [itemIndex, item] of asArray(unit?.[field]).entries()) {
          const itemWhere = `${where}.${field}[${itemIndex}]`;
          if (!Array.isArray(item?.evidence) || !item.evidence.length) {
            errors.push(`${itemWhere}.evidence is required`);
            continue;
          }
          for (const quote of item.evidence) {
            if (!evidenceExistsInChunks(quote, unitChunkIds, chunksById)) {
              errors.push(`${itemWhere}.evidence is not an exact short quote from this unit's source chunks`);
            }
          }
        }
      }
    }
  }
  return errors;
}

export function normalizeUnitSourceRefs(unit, chunksById) {
  const normalized = structuredClone(unit);
  normalized.source_refs = asArray(unit.source_refs).map((ref) => {
    const metadata = sourceRefMetadata(ref, chunksById);
    if (!metadata) throw new Error(`Cannot normalize provenance for ${unit.unit_key}: invalid chunk_ids`);
    return {
      ...ref,
      title: metadata.title || ref.title || metadata.url,
      url: metadata.url,
      source_id: metadata.source_id,
      source_sha256: metadata.source_sha256,
      page_start: metadata.page_start,
      page_end: metadata.page_end,
      evidence: asArray(ref.evidence).map(shortEvidence).slice(0, 3),
    };
  });
  return normalized;
}

function markdownEscape(value) {
  return String(value ?? "").replace(/([\\`*_{}\[\]<>])/g, "\\$1");
}

function list(lines, values) {
  if (!Array.isArray(values) || !values.length) return;
  for (const value of values) lines.push(`- ${value}`);
}

export function renderKnowledgeUnit(unit) {
  const lines = [
    `# ${unit.title}`,
    "",
    unit.summary,
    "",
    "## Operational objective",
    "",
    unit.objective,
    "",
    "## When this applies",
    "",
    unit.applicability,
  ];

  if (unit.prerequisites?.length) { lines.push("", "## Preconditions", ""); list(lines, unit.prerequisites); }
  if (unit.attack_surface?.length) { lines.push("", "## Attack surface", ""); list(lines, unit.attack_surface); }

  if (unit.operator_flow?.length) {
    lines.push("", "## Operator flow", "");
    for (const [index, step] of unit.operator_flow.entries()) {
      const action = typeof step === "string" ? step : step.action;
      const why = typeof step === "object" ? step.why : "";
      lines.push(`${index + 1}. ${action}${why ? ` — ${why}` : ""}`);
    }
  }

  if (unit.decision_points?.length) {
    lines.push("", "## Decision points", "");
    for (const point of unit.decision_points) {
      lines.push(`- **If:** ${point.condition}  `, `  **Then:** ${point.action}${point.rationale ? ` — ${point.rationale}` : ""}`);
    }
  }

  if (unit.validation_signals?.length) { lines.push("", "## Validation signals", ""); list(lines, unit.validation_signals); }
  if (unit.pivots?.length) { lines.push("", "## Pivots and variants", ""); list(lines, unit.pivots); }
  if (unit.failure_modes?.length) { lines.push("", "## Failure modes", ""); list(lines, unit.failure_modes); }

  if (unit.tool_usage?.length) {
    lines.push("", "## Tool usage", "");
    for (const tool of unit.tool_usage) lines.push(`- **${tool.tool}:** ${tool.use}${tool.pattern ? ` — ${tool.pattern}` : ""}`);
  }

  if (unit.source_refs?.length) {
    lines.push("", "## Sources and provenance", "");
    for (const ref of unit.source_refs) {
      const range = ref.page_start ? ` · pp. ${ref.page_start}${ref.page_end && ref.page_end !== ref.page_start ? `–${ref.page_end}` : ""}` : "";
      const digest = ref.source_sha256 ? ` · sha256:${String(ref.source_sha256).slice(0, 16)}…` : "";
      lines.push(`- [${markdownEscape(ref.title || ref.url)}](${ref.url})${range}${digest}`);
      for (const quote of (ref.evidence ?? []).slice(0, 3)) lines.push(`  - Evidence: “${shortEvidence(quote)}”`);
    }
  }
  return lines.join("\n").trim();
}

export function toCanonicalRecords(units, collection, { model = "z-ai/glm-5.2" } = {}) {
  return units.map((unit, index) => {
    const body = renderKnowledgeUnit(unit);
    const sourceRefs = (unit.source_refs ?? []).map((ref) => ({
      source_id: ref.source_id ?? null,
      title: ref.title,
      url: ref.url,
      source_sha256: ref.source_sha256 ?? null,
      page_start: ref.page_start ?? null,
      page_end: ref.page_end ?? null,
      chunk_ids: ref.chunk_ids ?? [],
      evidence: (ref.evidence ?? []).map(shortEvidence).slice(0, 3),
    }));
    const components = [
      ...(unit.attack_surface ?? []).slice(0, 5),
      ...(unit.tool_usage ?? []).slice(0, 5).map((item) => `${item.tool}: ${item.use}`),
    ];
    return {
      schema_version: "hugin.canonical.v2",
      id: `external-knowledge:${sha256(`${collection.id}:${unit.unit_key}`).slice(0, 28)}`,
      kind: "playbook",
      title: unit.title,
      content: body,
      category: unit.knowledge_type || collection.knowledge_profile || "offensive-web",
      language: collection.language || "en",
      tags: [...new Set(["external-distillation", collection.id, ...(unit.tags ?? [])])].slice(0, 24),
      publish_state: "core",
      facets: {
        distillation: {
          version: EXTERNAL_KNOWLEDGE_VERSION,
          unit_key: unit.unit_key,
          knowledge_type: unit.knowledge_type,
          objective: unit.objective,
          applicability: unit.applicability,
          source_refs: sourceRefs,
        },
      },
      source: {
        name: collection.title,
        input_file: `external:${collection.id}`,
        record_index: index,
        record_sha256: sha256(stableStringify(unit)),
        mapping_sha256: sha256(EXTERNAL_KNOWLEDGE_VERSION),
      },
      routing: {
        semantic_complexity: "complex",
        requested_enrichment: [],
        router_confidence: 1,
      },
      enrichment: {
        schema_version: "hugin.enrichment.v2",
        status: "complete",
        provider: "nvidia",
        model,
        summary: unit.summary,
        abstract: `${unit.objective} ${unit.applicability}`.trim(),
        card: {
          title: unit.title,
          purpose: unit.objective,
          technical_context: [unit.applicability, ...(unit.prerequisites ?? [])].filter(Boolean).join(" ").slice(0, 1200),
          mechanism: (unit.operator_flow ?? []).map((step, i) => `${i + 1}. ${typeof step === "string" ? step : step.action}`).join(" ").slice(0, 1800),
          components: components.slice(0, 10),
          key_points: [...(unit.validation_signals ?? []), ...(unit.decision_points ?? []).slice(0, 4).map((p) => `${p.condition} -> ${p.action}`)].slice(0, 10),
          artifacts: (unit.tool_usage ?? []).map((item) => `${item.tool}: ${item.pattern || item.use}`).slice(0, 10),
          tradecraft_context: [...(unit.pivots ?? []), ...(unit.attack_surface ?? [])].slice(0, 8),
          caveats: (unit.failure_modes ?? []).slice(0, 6),
        },
        tags: (unit.tags ?? []).slice(0, 16),
        concepts: unit.concepts ?? [],
        techniques: unit.techniques ?? [],
        entities: unit.entities ?? [],
        relations: unit.relations ?? [],
        mitre_candidates: unit.mitre_candidates ?? [],
      },
    };
  });
}
