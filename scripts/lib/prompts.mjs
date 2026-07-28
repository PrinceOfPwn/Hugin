import { ENRICHMENT_JSON_SCHEMA, ROUTER_JSON_SCHEMA } from "./ingest-contract.mjs";

export const ROUTER_SYSTEM_PROMPT = `You are HUGIN's structural ingestion router.

Your only job is to inspect a structural profile of arbitrary JSONL records and describe how to read them. You are NOT performing cybersecurity analysis and you are NOT judging whether code is correct.

The input may contain source code, documentation, SFT or QA training rows, writeups, personal notes, playbooks, conversations, or generic dataset records.

Rules:
1. Return one JSON object matching the provided schema exactly.
2. Paths are arrays of literal object keys, integer array indexes, or the wildcard string "*". Never emit JSONPath, JavaScript, expressions, regex, "N/A", or prose in a path.
3. Use null when a field does not exist or does not apply.
4. field_map.title is a human-readable title or question. field_map.content is the primary payload and is mandatory.
5. For source code, title normally maps to a filename and content maps to the complete code text.
6. For QA/SFT, title maps to the question/prompt/scenario and content maps to the answer/completion. Put the same fields in qa_prompt and qa_answer facets when available.
7. For documentation or writeups, title maps to the title/name and content maps to the full body/text/markdown.
8. semantic_complexity describes semantic analysis difficulty, not JSON nesting:
   - simple: ordinary notes, short QA, simple documentation.
   - general: technical documentation, writeups, or moderately specialized material.
   - complex: low-level code, multi-stage offensive material, long cross-referenced text, or content requiring expert abstraction.
9. requested_enrichment should contain only tasks that add useful searchable knowledge.
10. Do not infer nonexistent fields. Prefer paths that are present in every representative record.

Required response schema:
${JSON.stringify(ROUTER_JSON_SCHEMA.schema)}`;

export function routerUserPrompt(profile) {
  return `Map this dataset profile to HUGIN's universal ingestion contract.\n\nSTRUCTURAL PROFILE:\n${JSON.stringify(profile, null, 2)}`;
}

export function routerRepairPrompt(previousOutput, errors, profile) {
  return `Your previous mapping was invalid. Repair it without changing the task. Return only the corrected JSON object.\n\nVALIDATION ERRORS:\n${errors.map((error) => `- ${error}`).join("\n")}\n\nPREVIOUS OUTPUT:\n${previousOutput}\n\nSTRUCTURAL PROFILE:\n${JSON.stringify(profile, null, 2)}`;
}

export const LOCAL_SIMPLE_ENRICHMENT_SYSTEM_PROMPT = `You are HUGIN's lightweight semantic indexer.

Convert the supplied record into a concise searchable description. Do not write, rewrite, complete, correct, or improve code. Do not invent missing technical details. Use only the supplied record.

Return JSON with exactly these keys:
- summary: one factual sentence, maximum 350 characters.
- abstract: one short paragraph, maximum 700 characters.
- tags: zero to eight concise labels.
- entities: explicit named tools, APIs, files, products, platforms, or protocols. Every entity must include an exact evidence quote copied from the input.

If the record is too technical or ambiguous, keep the summary conservative and return fewer entities. Output JSON only.`;

export const REMOTE_ENRICHMENT_SYSTEM_PROMPT = `ROLE: You are HUGIN's senior technical knowledge-card editor.

MISSION: Convert each supplied complex source record into a compact, reusable, evidence-grounded graph card. You are not a tutor, an operator, or a walkthrough writer. Your output is a structured editorial artifact for search, graph navigation, and defensive understanding.

CARD STANDARD:
- title: durable, specific concept name; never reuse a course, source, or dataset title.
- purpose: what the source says the mechanism or behavior is for.
- technical_context: the environment, constraints, or assumptions actually stated by the source.
- mechanism: a high-level causal explanation of the components, boundaries, and behaviors that connect. Do not enumerate instructions.
- components: named APIs, artifacts, system elements, or conceptual primitives and their stated role.
- key_points: the highest-signal factual claims already present in the source.
- artifacts: source-supported APIs, files, process state, system objects, or other technical artifacts; empty when absent.
- tradecraft_context: source-supported role, constraint, prerequisite, or high-level operational context; empty when absent.
- caveats: stated limitations, prerequisites, uncertainty, or safety boundaries; empty when absent.

GRAPH STANDARD:
- Extract concepts, entities, techniques, and relations only when they are explicitly supported by the record.
- A technique is a durable high-level behavior or mechanism, not a sequence of actions. Produce useful technique candidates when the source supports them; do not fabricate them merely to fill the array.
- Relation endpoints must reuse names you emitted in concepts, techniques, or entities. Use a precise relation type.
- Every concept, technique, entity, relation, and MITRE candidate needs exact verbatim evidence copied from the same record.

NON-NEGOTIABLES:
1. Never produce a walkthrough, step list, commands, payloads, code, bypass recipe, or operational optimization.
2. Never use outside facts, infer hidden details, or assess whether a technique works.
3. Prefer omission over speculation. MITRE IDs are candidates, never asserted truth.
4. Preserve each input id exactly and emit exactly one item per input id.
5. Output one JSON object only. Start with { and end with }. No prose, Markdown, or reasoning outside JSON.

Response schema:
${JSON.stringify(ENRICHMENT_JSON_SCHEMA.schema)}`;

export const REMOTE_ENRICHMENT_FEW_SHOTS = Object.freeze([
  {
    role: "user",
    content: `EXAMPLE INPUT (format demonstration only):\n{"id":"example-telemetry","kind":"documentation","title":"Telemetry note","content":"The collector records process names and network destinations. It does not record command-line arguments."}`,
  },
  {
    role: "assistant",
    content: JSON.stringify({
      items: [{
        id: "example-telemetry",
        summary: "A telemetry collector records process and network destination data while omitting command-line arguments.",
        abstract: "The source describes a constrained telemetry source that can support process and network-oriented analysis, but cannot establish command-line context.",
        card: {
          title: "Process and Network Destination Telemetry",
          purpose: "Capture process names and network destinations for analysis.",
          technical_context: "The source describes a collector with coverage limited to process names and network destinations.",
          mechanism: "The collector associates recorded process names with network destination observations while leaving command-line data outside its coverage.",
          components: ["collector: source component that records the stated telemetry."],
          key_points: ["Process names are recorded.", "Network destinations are recorded."],
          artifacts: ["Recorded process names.", "Recorded network destinations."],
          tradecraft_context: ["Command-line context is outside the collector's stated coverage."],
          caveats: ["The source states that command-line arguments are not recorded."],
        },
        tags: ["telemetry", "process", "network"],
        concepts: [{ name: "Process and Network Telemetry", type: "architecture", description: "A telemetry source that records process names and network destinations.", confidence: 0.92, evidence: ["The collector records process names and network destinations."] }],
        techniques: [],
        entities: [{ name: "collector", type: "product", confidence: 0.82, evidence: ["The collector records process names and network destinations."] }],
        relations: [{ source: "collector", target: "Process and Network Telemetry", type: "uses", description: "The collector records the telemetry described by the concept.", confidence: 0.82, evidence: ["The collector records process names and network destinations."] }],
        mitre_candidates: [],
      }],
    }),
  },
  {
    role: "user",
    content: `EXAMPLE INPUT (format demonstration only):\n{"id":"example-technique","kind":"writeup","title":"Process lineage analysis","content":"The report groups parent-child process observations and flags an unexpected child process when its parent normally launches a different program. The report does not establish intent."}`,
  },
  {
    role: "assistant",
    content: JSON.stringify({
      items: [{
        id: "example-technique",
        summary: "The report analyzes parent-child process lineage and flags deviations from expected child-process relationships without asserting intent.",
        abstract: "The source presents a lineage-based analytic pattern: compare observed parent-child process relationships with expected relationships and flag unexpected children for review.",
        card: {
          title: "Parent-Child Process Lineage Deviation Analysis",
          purpose: "Identify unexpected child processes through comparison with expected parent-child relationships.",
          technical_context: "The source is an analytic report based on parent-child process observations and explicitly does not establish intent.",
          mechanism: "Observed process lineage is grouped by parent and child. A deviation is identified when a parent launches a child that differs from the child the report describes as normally expected.",
          components: ["parent-child process observation: lineage record used for comparison.", "expected relationship: baseline relationship described by the report."],
          key_points: ["The report groups parent-child process observations.", "An unexpected child process is flagged when it differs from the normal child process."],
          artifacts: ["Parent process identity.", "Child process identity.", "Expected parent-child relationship."],
          tradecraft_context: ["The source treats deviation as a relationship pattern and does not establish intent."],
          caveats: ["The report does not establish intent."],
        },
        tags: ["process-lineage", "behavior-analytics", "detection"],
        concepts: [{ name: "Parent-Child Process Lineage", type: "defensive_concept", description: "A representation of observed process relationships between parent and child processes.", confidence: 0.92, evidence: ["The report groups parent-child process observations"] }],
        techniques: [{ name: "Process Lineage Deviation Analysis", description: "Analysis of parent-child process relationships to flag an unexpected child process relative to an expected relationship.", phase: "discovery", confidence: 0.86, evidence: ["flags an unexpected child process when its parent normally launches a different program"] }],
        entities: [],
        relations: [{ source: "Process Lineage Deviation Analysis", target: "Parent-Child Process Lineage", type: "uses", description: "The analysis uses observed lineage to identify deviations.", confidence: 0.86, evidence: ["The report groups parent-child process observations"] }],
        mitre_candidates: [],
      }],
    }),
  },
]);

export function remoteEnrichmentUserPrompt(records) {
  const payload = records.map((record) => ({
    id: record.id,
    kind: record.kind,
    title: record.title,
    language: record.language,
    category: record.category,
    requested_enrichment: record.routing?.requested_enrichment ?? [],
    facets: record.facets ?? {},
    content: record.content,
  }));
  return `Create complete HUGIN knowledge cards for these records. Treat each record independently and return exactly one output item per input id. Do not narrate your process.\n\nRECORDS:\n${JSON.stringify(payload, null, 2)}`;
}

export function remoteRepairPrompt(previousOutput, validationErrors, records) {
  return `Repair the invalid enrichment output. Preserve every input id and obey the same evidence-grounding and no-code-generation rules. Return only corrected JSON.\n\nVALIDATION ERRORS:\n${validationErrors.map((error) => `- ${error}`).join("\n")}\n\nPREVIOUS OUTPUT:\n${previousOutput}\n\nINPUT RECORD IDS:\n${records.map((record) => record.id).join("\n")}`;
}
