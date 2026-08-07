import crypto from "node:crypto";

export const EXTERNAL_KNOWLEDGE_VERSION = "hugin.external-knowledge.v1";
export const DEFAULT_CHUNK_CHARS = 48000;
export const DEFAULT_BATCH_CHARS = 220000;
export const MAX_EVIDENCE_CHARS = 220;

export const sha256 = (value) => crypto.createHash("sha256").update(String(value)).digest("hex");

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

export function decodeHtmlEntities(value) {
  const named = {
    amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ",
    ndash: "–", mdash: "—", hellip: "…",
  };
  return String(value ?? "")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(Number.parseInt(n, 16)))
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

export function chunkPdfText(text, { chunkChars = DEFAULT_CHUNK_CHARS, overlapPages = 1, maxPages = Infinity } = {}) {
  const rawPages = String(text ?? "").split("\f");
  const pages = rawPages
    .slice(0, Number.isFinite(maxPages) ? Math.max(0, maxPages) : undefined)
    .map((page, index) => ({ page: index + 1, text: compactText(page) }))
    .filter((page) => page.text);
  if (!pages.length) return [];

  const chunks = [];
  let cursor = 0;
  while (cursor < pages.length) {
    const start = cursor;
    let end = cursor;
    let chars = 0;
    while (end < pages.length) {
      const next = pages[end].text.length + (end > start ? 2 : 0);
      if (end > start && chars + next > chunkChars) break;
      chars += next;
      end++;
    }
    if (end === start) end++;
    const selected = pages.slice(start, end);
    chunks.push({
      page_start: selected[0].page,
      page_end: selected.at(-1).page,
      text: selected.map((page) => page.text).join("\n\n"),
    });
    if (end >= pages.length) break;
    cursor = Math.max(start + 1, end - Math.max(0, overlapPages));
  }
  return chunks;
}

export function chunkPlainText(text, { chunkChars = DEFAULT_CHUNK_CHARS, overlapChars = 1600 } = {}) {
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

export function validateKnowledgeUnits(value, { root = "units", chunksById = null } = {}) {
  const errors = [];
  if (!value || typeof value !== "object" || !Array.isArray(value[root])) return [`${root} array is required`];
  const keys = new Set();
  for (const [index, unit] of value[root].entries()) {
    const where = `${root}[${index}]`;
    for (const field of ["unit_key", "title", "knowledge_type", "summary", "objective", "applicability"]) {
      if (typeof unit?.[field] !== "string" || !unit[field].trim()) errors.push(`${where}.${field} must be a non-empty string`);
    }
    if (unit?.unit_key) {
      if (keys.has(unit.unit_key)) errors.push(`${where}.unit_key must be unique`);
      keys.add(unit.unit_key);
    }
    for (const field of STRING_ARRAY_FIELDS) if (!Array.isArray(unit?.[field])) errors.push(`${where}.${field} must be an array`);
    for (const field of ["operator_flow", "decision_points", "tool_usage", "source_refs", "concepts", "techniques", "entities", "relations", "mitre_candidates"]) {
      if (!Array.isArray(unit?.[field])) errors.push(`${where}.${field} must be an array`);
    }
    if (!unit?.source_refs?.length) errors.push(`${where}.source_refs must contain grounded provenance`);

    const localNames = new Set([
      ...(unit?.concepts ?? []).map((item) => item?.name),
      ...(unit?.techniques ?? []).map((item) => item?.name),
      ...(unit?.entities ?? []).map((item) => item?.name),
    ].filter(Boolean));
    for (const [relationIndex, relation] of (unit?.relations ?? []).entries()) {
      if (!localNames.has(relation?.source) || !localNames.has(relation?.target)) {
        errors.push(`${where}.relations[${relationIndex}] endpoints must reuse names from the same unit`);
      }
    }

    if (chunksById) {
      const unitChunkIds = [...new Set((unit?.source_refs ?? []).flatMap((ref) => ref?.chunk_ids ?? []))];
      for (const [refIndex, ref] of (unit?.source_refs ?? []).entries()) {
        const refWhere = `${where}.source_refs[${refIndex}]`;
        if (typeof ref?.url !== "string" || !/^https?:\/\//i.test(ref.url)) errors.push(`${refWhere}.url must be http(s)`);
        if (!Array.isArray(ref?.chunk_ids) || !ref.chunk_ids.length) errors.push(`${refWhere}.chunk_ids is required`);
        if (!Array.isArray(ref?.evidence) || !ref.evidence.length) errors.push(`${refWhere}.evidence is required`);
        for (const quote of ref?.evidence ?? []) {
          if (!evidenceExistsInChunks(quote, ref.chunk_ids, chunksById)) errors.push(`${refWhere}.evidence is not an exact short quote from referenced chunks`);
        }
      }

      for (const field of ["concepts", "techniques", "entities", "relations", "mitre_candidates"]) {
        for (const [itemIndex, item] of (unit?.[field] ?? []).entries()) {
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
      lines.push(`- [${markdownEscape(ref.title || ref.url)}](${ref.url})${range}`);
      for (const quote of (ref.evidence ?? []).slice(0, 3)) lines.push(`  - Evidence: “${shortEvidence(quote)}”`);
    }
  }
  return lines.join("\n").trim();
}

export function toCanonicalRecords(units, collection, { model = "z-ai/glm-5.2" } = {}) {
  return units.map((unit, index) => {
    const body = renderKnowledgeUnit(unit);
    const sourceRefs = (unit.source_refs ?? []).map((ref) => ({
      title: ref.title,
      url: ref.url,
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
        input_file: `external:${collection.source}`,
        record_index: index,
        record_sha256: sha256(JSON.stringify(unit)),
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
