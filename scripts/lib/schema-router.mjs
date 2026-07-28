import { ROUTER_VERSION } from "./ingest-contract.mjs";

/**
 * Cheap, explainable classifications for formats whose intent is unambiguous.
 * This is deliberately a small positive list: every other shape is routed to
 * the cloud schema mapper rather than guessed from a growing rule catalogue.
 */
export function classifyKnownSchema(records, sourceName) {
  const first = records[0] ?? {};
  const has = (key) => Object.hasOwn(first, key);
  const content = has("content") || has("code") || has("body") || has("text");

  if ((has("file_name") || has("file_type") || has("relative_path")) && content) {
    return codeMapping(first, sourceName);
  }
  if ((has("prompt") || has("question")) && has("chosen") && has("rejected")) {
    return preferenceMapping(first, sourceName);
  }
  if ((has("prompt") || has("question")) && (has("answer") || has("response") || has("completion"))) {
    return qaMapping(first, sourceName);
  }
  if (has("title") && (has("body") || has("content") || has("text"))) {
    return documentationMapping(first, sourceName);
  }
  return null;
}

export function deterministicFallback(records, sourceName) {
  const first = records[0] ?? {};
  return baseMapping({
    sourceName,
    kind: "unknown",
    complexity: "general",
    confidence: 0.2,
    language: "unknown",
    first,
    title: pathForKey(first, ["file_name", "title", "name", "question", "prompt", "scenario", "unit_id", "id"]),
    content: pathForKey(first, ["content", "body", "text", "answer", "response", "completion", "output", "assessment", "description", "code"]),
    requested: [],
    notes: "No deterministic schema match and no valid cloud mapping. Preserved without semantic enrichment.",
  });
}

function codeMapping(first, sourceName) {
  return baseMapping({
    sourceName, kind: "source_code", complexity: "complex", confidence: 1, language: first.file_type ?? "raw_code", first,
    title: pathForKey(first, ["file_name", "relative_path", "title", "id"]),
    content: pathForKey(first, ["content", "code", "body", "text"]),
    requested: fullEnrichment(),
    facets: { code: { file_name: pathForKey(first, ["file_name"]), relative_path: pathForKey(first, ["relative_path"]), language: pathForKey(first, ["file_type", "language"]) } },
    notes: "Deterministic source-code mapping.",
  });
}

function preferenceMapping(first, sourceName) {
  return baseMapping({
    sourceName, kind: "training_preference", complexity: "simple", confidence: 1, language: first.language ?? "en", first,
    title: pathForKey(first, ["prompt", "question", "id"]),
    content: pathForKey(first, ["chosen"]),
    requested: [],
    facets: { preference: {
      prompt: pathForKey(first, ["prompt", "question"]),
      chosen: pathForKey(first, ["chosen"]),
      rejected: pathForKey(first, ["rejected"]),
      mutation_type: pathForKey(first, ["mutation_type"]),
      source_model: pathForKey(first, ["source_model"]),
      judge_model: pathForKey(first, ["judge_model"]),
    } },
    notes: "Deterministic preference-pair mapping. Kept as training provenance; semantic extraction is intentionally skipped.",
  });
}

function qaMapping(first, sourceName) {
  return baseMapping({
    sourceName, kind: "training_qa", complexity: "general", confidence: 1, language: first.language ?? "en", first,
    title: pathForKey(first, ["prompt", "question", "scenario", "id"]),
    content: pathForKey(first, ["answer", "response", "completion", "output"]),
    requested: fullEnrichment(),
    facets: { qa: { prompt: pathForKey(first, ["prompt", "question"]), answer: pathForKey(first, ["answer", "response", "completion"]) } },
    notes: "Deterministic question-and-answer mapping.",
  });
}

function documentationMapping(first, sourceName) {
  return baseMapping({
    sourceName, kind: "documentation", complexity: "general", confidence: 1, language: first.language ?? "en", first,
    title: pathForKey(first, ["title", "name", "headline"]),
    content: pathForKey(first, ["body", "content", "text", "details"]),
    requested: fullEnrichment(), notes: "Deterministic documentation mapping.",
  });
}

function baseMapping({ sourceName, kind, complexity, confidence, language, first, title, content, requested, facets, notes }) {
  return {
    schema_version: ROUTER_VERSION,
    source_name: sourceName,
    kind,
    record_shape: "mixed",
    detected_language: language,
    semantic_complexity: complexity,
    confidence,
    field_map: {
      id: pathForKey(first, ["id", "unit_id", "uuid", "source_record_id"]),
      title: title ?? null,
      content: content ?? { path: [], join: null },
      category: pathForKey(first, ["category", "task_type", "topic", "file_type", "language"]),
      tags: pathForKey(first, ["tags", "labels"]),
      language: pathForKey(first, ["language", "file_type", "lang"]),
      source: pathForKey(first, ["source", "source_name", "origin", "source_model"]),
    },
    constants: { category: null, publish_state: "core" },
    facets: facets ?? {},
    requested_enrichment: requested,
    notes,
  };
}

function pathForKey(record, candidates) {
  for (const key of candidates) if (Object.hasOwn(record, key)) return { path: [key], join: null };
  return null;
}

function fullEnrichment() {
  return ["summary", "concepts", "techniques", "entities", "relations", "mitre_candidates", "tags"];
}
