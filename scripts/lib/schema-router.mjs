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

  // Video notes (ingest-video.mjs) — checked first so the video facet is preserved.
  if (has("video_notes") && has("title") && has("body")) {
    return videoNotesMapping(first, sourceName);
  }

  // Project bundles (wrap-inputs.mjs) — checked first so the project facet is preserved.
  if (has("project_manifest") && (has("file_name") || has("relative_path")) && (has("content") || has("code"))) {
    return projectSourceMapping(first, sourceName);
  }
  if (has("project_manifest") && has("title") && (has("body") || has("content") || has("text"))) {
    return projectDocumentationMapping(first, sourceName);
  }

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

function projectSourceMapping(first, sourceName) {
  const projectName = first?.project_manifest?.project ?? sourceName;
  return baseMapping({
    sourceName, kind: "project_source_code", complexity: "complex", confidence: 1, language: first.file_type ?? "raw_code", first,
    title: pathForKey(first, ["file_name", "relative_path", "title", "id"]),
    content: pathForKey(first, ["content", "code", "body", "text"]),
    requested: fullEnrichment(),
    facets: {
      code: { file_name: pathForKey(first, ["file_name"]), relative_path: pathForKey(first, ["relative_path"]), language: pathForKey(first, ["file_type", "language"]) },
      // Each nested facet value must be null OR a {path, join} spec — literals
      // like the previous `name: projectName` fail isValidFacetSpec. Emit path
      // specs that resolve at apply-time via resolveFacet.
      project: {
        name: { path: ["project_manifest", "project"], join: null },
        member_path: { path: ["project_manifest", "relative_path"], join: null },
        role: { path: ["project_manifest", "role"], join: null },
      },
    },
    notes: `Deterministic project source-code mapping (bundle=${projectName}).`,
  });
}

function videoNotesMapping(first, sourceName) {
  const videoSource = first?.video_notes?.source_file ?? sourceName;
  return baseMapping({
    sourceName, kind: "video_notes", complexity: "complex", confidence: 1, language: first.language ?? "en", first,
    title: pathForKey(first, ["title"]),
    content: pathForKey(first, ["body", "content", "text"]),
    requested: fullEnrichment(),
    facets: {
      video: {
        source_file: pathForKey(first, ["video_notes"]),
        fingerprint: pathForKey(first, ["video_notes"]),
        duration_sec: pathForKey(first, ["video_notes"]),
        model: pathForKey(first, ["video_notes"]),
        segments: pathForKey(first, ["video_notes"]),
      },
    },
    notes: `Deterministic video-notes mapping (source=${videoSource}).`,
  });
}

function projectDocumentationMapping(first, sourceName) {
  const projectName = first?.project_manifest?.project ?? sourceName;
  return baseMapping({
    sourceName, kind: "project_documentation", complexity: "general", confidence: 1, language: first.language ?? "en", first,
    title: pathForKey(first, ["title", "name", "headline", "file_name"]),
    content: pathForKey(first, ["body", "content", "text", "details"]),
    requested: fullEnrichment(),
    facets: {
      // Same shape as projectSourceMapping — path specs, not string literals.
      project: {
        name: { path: ["project_manifest", "project"], join: null },
        member_path: { path: ["project_manifest", "relative_path"], join: null },
        role: { path: ["project_manifest", "role"], join: null },
      },
    },
    notes: `Deterministic project documentation mapping (bundle=${projectName}).`,
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
