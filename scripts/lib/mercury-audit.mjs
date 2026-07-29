import crypto from "node:crypto";

export const CONTENT_TYPES = [
  "qa",
  "source_code",
  "code_snippet",
  "technical_note",
  "procedure",
  "command_reference",
  "tool",
  "technique",
  "concept",
  "configuration",
  "dataset_record",
  "malformed",
  "unknown",
];

export const QUALITY_ISSUES = [
  "incorrect_qa_classification",
  "wrong_type",
  "broken_markdown",
  "flattened_code",
  "truncated_content",
  "duplicate_content",
  "garbled_text",
  "title_mismatch",
  "summary_mismatch",
  "invalid_mitre",
  "weak_tags",
  "missing_relations",
  "missing_summary",
  "none",
];

export const RELATION_TYPES = [
  "requires",
  "enables",
  "implements",
  "references",
  "uses",
  "mitigates",
  "detects",
  "related_to",
];

export const auditJsonSchema = {
  name: "hugin_entity_audit",
  strict: true,
  schema: {
    type: "object",
    additionalProperties: false,
    properties: {
      detected_content_type: { type: "string", enum: CONTENT_TYPES },
      current_type_valid: { type: "boolean" },
      language: { type: ["string", "null"] },
      suggested_title: { type: ["string", "null"] },
      summary: { type: "string" },
      tags: { type: "array", maxItems: 12, items: { type: "string" } },
      mitre_candidates: {
        type: "array",
        maxItems: 8,
        items: {
          type: "object",
          additionalProperties: false,
          properties: {
            id: { type: "string" },
            confidence: { type: "number", minimum: 0, maximum: 1 },
            evidence: { type: "string" },
          },
          required: ["id", "confidence", "evidence"],
        },
      },
      entities: {
        type: "array",
        maxItems: 20,
        items: {
          type: "object",
          additionalProperties: false,
          properties: { name: { type: "string" }, type: { type: "string" } },
          required: ["name", "type"],
        },
      },
      relation_candidates: {
        type: "array",
        maxItems: 12,
        items: {
          type: "object",
          additionalProperties: false,
          properties: {
            target_hint: { type: "string" },
            relation: { type: "string", enum: RELATION_TYPES },
            confidence: { type: "number", minimum: 0, maximum: 1 },
            evidence: { type: "string" },
          },
          required: ["target_hint", "relation", "confidence", "evidence"],
        },
      },
      quality_issues: { type: "array", items: { type: "string", enum: QUALITY_ISSUES } },
      recommended_renderer: { type: "string", enum: ["qa", "code", "markdown", "procedure", "reference", "raw"] },
      safe_fixes: {
        type: "object",
        additionalProperties: false,
        properties: {
          remove_qa_prefix: { type: "boolean" },
          extract_technical_answer: { type: "boolean" },
          set_content_format: { type: ["string", "null"], enum: ["markdown", "code", "text", null] },
          replace_summary: { type: "boolean" },
          reclassify_node: { type: "boolean" },
        },
        required: ["remove_qa_prefix", "extract_technical_answer", "set_content_format", "replace_summary", "reclassify_node"],
      },
      confidence: { type: "number", minimum: 0, maximum: 1 },
      needs_review: { type: "boolean" },
      rationale: { type: "string" },
    },
    required: [
      "detected_content_type", "current_type_valid", "language", "suggested_title", "summary", "tags",
      "mitre_candidates", "entities", "relation_candidates", "quality_issues", "recommended_renderer",
      "safe_fixes", "confidence", "needs_review", "rationale",
    ],
  },
};

const EXTENSION_LANGUAGES = new Map([
  ["asm", "x86_64_assembly"], ["s", "assembly"], ["rs", "rust"], ["py", "python"],
  ["js", "javascript"], ["mjs", "javascript"], ["ts", "typescript"], ["tsx", "typescript"],
  ["jsx", "javascript"], ["c", "c"], ["h", "c"], ["cc", "cpp"], ["cpp", "cpp"],
  ["hpp", "cpp"], ["cs", "csharp"], ["go", "go"], ["java", "java"], ["kt", "kotlin"],
  ["swift", "swift"], ["rb", "ruby"], ["php", "php"], ["ps1", "powershell"], ["sh", "shell"],
  ["bash", "shell"], ["yml", "yaml"], ["yaml", "yaml"], ["json", "json"], ["toml", "toml"],
]);

export function stableHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

export function truncateForPrompt(value, maxChars = 14000) {
  const text = String(value ?? "").replace(/\u0000/g, "");
  if (text.length <= maxChars) return text;
  const head = Math.floor(maxChars * 0.68);
  const tail = maxChars - head;
  return `${text.slice(0, head)}\n\n[...TRUNCATED BY HUGIN AUDITOR...]\n\n${text.slice(-tail)}`;
}

export function detectLanguage(node = {}, content = "") {
  for (const candidate of [node.file, node.path, node.label, node.name].filter(Boolean).map(String)) {
    const match = candidate.match(/\.([a-z0-9+_-]{1,8})(?:\b|$)/i);
    if (match && EXTENSION_LANGUAGES.has(match[1].toLowerCase())) return EXTENSION_LANGUAGES.get(match[1].toLowerCase());
  }
  const sample = String(content).slice(0, 8000);
  if (/\b(?:EXTRN|PROC|ENDP|DWORD|QWORD)\b/i.test(sample) && /\b(?:mov|syscall|ret)\b/i.test(sample)) return "x86_64_assembly";
  if (/\bfn\s+[a-zA-Z_]\w*\s*\(|\blet\s+mut\b|::[a-zA-Z_]\w*/.test(sample)) return "rust";
  if (/\bdef\s+[a-zA-Z_]\w*\s*\(|\bimport\s+[a-zA-Z_]/.test(sample)) return "python";
  if (/\b(?:const|let|var)\s+[a-zA-Z_$]\w*\s*=|=>|\bfunction\s+[a-zA-Z_$]/.test(sample)) return "javascript";
  if (/\b#include\s*[<"]|\b(?:int|void|char)\s+\w+\s*\(/.test(sample)) return "c_or_cpp";
  if (/\bparam\s*\(|\bGet-[A-Z]\w+|\$env:[A-Za-z_]/.test(sample)) return "powershell";
  return null;
}

export function looksLikeQuestion(value) {
  const text = String(value ?? "").trim();
  if (!text) return false;
  return /\?$/.test(text) || /^(?:how|why|what|when|where|which|who|can|could|should|does|do|is|are|explain|describe|compare)\b/i.test(text);
}

export function looksLikeCode(value) {
  const text = String(value ?? "");
  if (!text.trim()) return false;
  const lines = text.split(/\r?\n/).filter((line) => line.trim());
  const patterns = [
    /\b(?:EXTRN|PROC|ENDP|DWORD|QWORD|syscall|mov\s+r\d+)\b/i,
    /\b(?:def|class|function|fn|struct|enum|interface)\s+[A-Za-z_$]/,
    /[{}();]\s*$/m,
    /^\s*(?:import|from|#include|using|package)\b/m,
    /^\s*(?:SELECT|INSERT|UPDATE|DELETE|CREATE TABLE)\b/im,
    /```(?:\w+)?\s*[\s\S]*```/,
  ];
  const matches = patterns.reduce((sum, pattern) => sum + Number(pattern.test(text)), 0);
  const symbolicLines = lines.filter((line) => /[{}();=<>]|\b(?:mov|call|ret|jmp|push|pop)\b/i.test(line)).length;
  return matches >= 1 || (lines.length >= 3 && symbolicLines / lines.length >= 0.35);
}

export function extractQaSections(content) {
  const text = String(content ?? "");
  const scenarioHeader = "## 🎯 Research Context & Scenario";
  const answerHeader = "## 🔬 Full Technical Analysis";
  if (!text.includes(scenarioHeader) || !text.includes(answerHeader)) return null;
  const afterScenario = text.split(scenarioHeader)[1] ?? "";
  const [scenarioPart, rest] = afterScenario.split(answerHeader);
  const scenario = String(scenarioPart ?? "").replace(/^\s+|\s+$/g, "").replace(/\n---\s*$/s, "").trim();
  const answer = String(rest ?? "").split(/\n---\s*\n/)[0].trim();
  return { scenario, answer };
}

export function inspectHeuristically(node, content) {
  const sections = extractQaSections(content);
  const scenario = sections?.scenario ?? node.prompt ?? "";
  const answer = sections?.answer ?? content;
  const language = detectLanguage(node, answer);
  const codeLike = looksLikeCode(answer);
  const questionLike = looksLikeQuestion(scenario);
  const qaTyped = String(node.type ?? "").toLowerCase().includes("qa") || String(node.galaxyId ?? "") === "tradecraft_qa";
  const label = String(node.label ?? node.name ?? "");
  const filenamePrompt = /^\s*[\w.-]+\.[a-z0-9]{1,8}\s*$/i.test(String(scenario).trim());
  const issues = [];
  if (qaTyped && codeLike && (!questionLike || filenamePrompt)) issues.push("incorrect_qa_classification");
  if (codeLike && /\S[ \t]{2,}\S/.test(answer) === false && answer.split(/\r?\n/).length <= 3 && answer.length > 300) issues.push("flattened_code");
  if (/^QA\s*[·:-]/i.test(label) && (!questionLike || codeLike)) issues.push("title_mismatch");
  if (!String(node.summary ?? node.description ?? "").trim()) issues.push("missing_summary");
  if (!Array.isArray(node.tags) || node.tags.length < 2) issues.push("weak_tags");
  return { qaTyped, codeLike, questionLike, filenamePrompt, language, issues: [...new Set(issues)], scenario: truncateForPrompt(scenario, 2500), answer: truncateForPrompt(answer, 14000) };
}

export function clamp(value, min = 0, max = 1) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(max, Math.max(min, number)) : min;
}

export function limitWords(value, maxWords = 100) {
  const words = String(value ?? "").trim().split(/\s+/).filter(Boolean);
  return words.length <= maxWords ? words.join(" ") : `${words.slice(0, maxWords).join(" ")}…`;
}

export function normalizeTag(value) {
  return String(value ?? "").trim().toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9_.+#-]/g, "").replace(/-{2,}/g, "-").replace(/^-|-$/g, "").slice(0, 48);
}

export function normalizeAudit(raw, node, heuristic) {
  const result = raw && typeof raw === "object" ? raw : {};
  const detected = CONTENT_TYPES.includes(result.detected_content_type) ? result.detected_content_type : heuristic.codeLike ? "code_snippet" : "unknown";
  const tags = [...new Set((Array.isArray(result.tags) ? result.tags : []).map(normalizeTag).filter((tag) => tag.length >= 2))].slice(0, 12);
  const mitre = (Array.isArray(result.mitre_candidates) ? result.mitre_candidates : []).map((item) => ({
    id: String(item?.id ?? "").toUpperCase().trim(), confidence: clamp(item?.confidence), evidence: String(item?.evidence ?? "").trim().slice(0, 400),
  })).filter((item) => /^T\d{4}(?:\.\d{3})?$/.test(item.id) && item.evidence).slice(0, 8);
  const relations = (Array.isArray(result.relation_candidates) ? result.relation_candidates : []).map((item) => ({
    target_hint: String(item?.target_hint ?? "").trim().slice(0, 160), relation: RELATION_TYPES.includes(item?.relation) ? item.relation : "related_to",
    confidence: clamp(item?.confidence), evidence: String(item?.evidence ?? "").trim().slice(0, 400),
  })).filter((item) => item.target_hint && item.evidence).slice(0, 12);
  const issues = [...new Set([...heuristic.issues, ...(Array.isArray(result.quality_issues) ? result.quality_issues.filter((issue) => QUALITY_ISSUES.includes(issue)) : [])])].filter((issue) => issue !== "none");
  return {
    entity_id: String(node.id),
    source_hash: stableHash(JSON.stringify({ node, content: heuristic.answer })).slice(0, 20),
    detected_content_type: detected,
    current_content_type: String(node.type ?? "unknown"),
    current_type_valid: Boolean(result.current_type_valid),
    language: result.language ? String(result.language).slice(0, 80) : heuristic.language,
    suggested_title: result.suggested_title ? String(result.suggested_title).trim().slice(0, 180) : null,
    summary: limitWords(result.summary, 100),
    tags,
    mitre_candidates: mitre,
    entities: (Array.isArray(result.entities) ? result.entities : []).map((item) => ({ name: String(item?.name ?? "").trim().slice(0, 160), type: String(item?.type ?? "unknown").trim().slice(0, 80) })).filter((item) => item.name).slice(0, 20),
    relation_candidates: relations,
    quality_issues: issues.length ? issues : ["none"],
    recommended_renderer: ["qa", "code", "markdown", "procedure", "reference", "raw"].includes(result.recommended_renderer) ? result.recommended_renderer : detected === "source_code" || detected === "code_snippet" ? "code" : "markdown",
    safe_fixes: {
      remove_qa_prefix: Boolean(result.safe_fixes?.remove_qa_prefix),
      extract_technical_answer: Boolean(result.safe_fixes?.extract_technical_answer),
      set_content_format: ["markdown", "code", "text"].includes(result.safe_fixes?.set_content_format) ? result.safe_fixes.set_content_format : null,
      replace_summary: Boolean(result.safe_fixes?.replace_summary),
      reclassify_node: Boolean(result.safe_fixes?.reclassify_node),
    },
    confidence: clamp(result.confidence),
    needs_review: Boolean(result.needs_review) || issues.some((issue) => ["garbled_text", "truncated_content", "duplicate_content"].includes(issue)),
    rationale: String(result.rationale ?? "").trim().slice(0, 600),
    heuristic: { qa_typed: heuristic.qaTyped, code_like: heuristic.codeLike, question_like: heuristic.questionLike, filename_prompt: heuristic.filenamePrompt },
    audited_at: new Date().toISOString(),
  };
}

export function buildMessages(node, content, heuristic) {
  const metadata = {
    id: node.id, type: node.type, label: node.label ?? node.name, summary: node.summary ?? node.description,
    category: node.category, topic: node.topic, tags: node.tags, mitre: node.mitre, file: node.file,
    galaxyId: node.galaxyId,
    heuristic: { code_like: heuristic.codeLike, question_like: heuristic.questionLike, filename_prompt: heuristic.filenamePrompt, detected_language: heuristic.language, issues: heuristic.issues },
  };
  const system = `You audit entities in HUGIN, an offensive-security knowledge graph.
This is classification and extraction, not free-form expert writing.
Use ONLY evidence present in the supplied metadata/content. Do not invent behavior, MITRE IDs, relations, or missing code.
A Q&A entity requires an actual question/scenario plus an answer. A filename such as syscalls.asm used as the prompt is not a question.
When content is code, distinguish a complete source artifact from a small code snippet. Preserve uncertainty.
Summaries must be factual, at most 100 words, and grounded in the source.
MITRE candidates require explicit behavior and a short evidence statement. Return no candidate when uncertain.
Relations are candidates only. Prefer concrete target hints such as an API, technique, primitive, file, or existing concept.
Tags must be specific technical terms, not generic words such as security, exploit, vulnerability, code, or analysis.
Safe fixes must be true only when they can be applied without reconstructing missing information.

FEW-SHOT 1 — code incorrectly imported as QA:
Input label: QA · Exploit Development · syscalls.asm
Scenario: syscalls.asm
Answer begins: EXTRN g_NtAllocateVirtualMemorySSN:DWORD ... mov r10, rcx ... syscall
Expected: detected_content_type=source_code, current_type_valid=false, language=x86_64_assembly, quality_issues includes incorrect_qa_classification, recommended_renderer=code, remove_qa_prefix=true, extract_technical_answer=true. Do not claim indirect syscalls unless explicit.

FEW-SHOT 2 — genuine QA:
Scenario: Why does Kerberoasting target service accounts?
Answer: explanatory prose about requesting service tickets and cracking them offline.
Expected: detected_content_type=qa, current_type_valid=true, recommended_renderer=qa.

FEW-SHOT 3 — technical note with embedded command:
Scenario is a heading, not a question. Body explains one procedure and includes a short PowerShell command.
Expected: detected_content_type=technical_note or procedure, not source_code merely because a command exists.

Return exactly the structured object required by the JSON schema.`;
  return [{ role: "system", content: system }, { role: "user", content: `ENTITY METADATA\n${JSON.stringify(metadata, null, 2)}\n\nENTITY CONTENT\n${truncateForPrompt(content, 16000)}` }];
}

export function summarizeAudits(results) {
  const byType = {};
  const byIssue = {};
  let review = 0;
  let reclassify = 0;
  let codeAsQa = 0;
  for (const item of results) {
    byType[item.detected_content_type] = (byType[item.detected_content_type] ?? 0) + 1;
    for (const issue of item.quality_issues ?? []) byIssue[issue] = (byIssue[issue] ?? 0) + 1;
    if (item.needs_review) review++;
    if (item.safe_fixes?.reclassify_node) reclassify++;
    if (item.quality_issues?.includes("incorrect_qa_classification")) codeAsQa++;
  }
  return {
    generated_at: new Date().toISOString(), total: results.length, needs_review: review,
    reclassification_candidates: reclassify, incorrect_qa_candidates: codeAsQa,
    by_detected_type: Object.fromEntries(Object.entries(byType).sort((a, b) => b[1] - a[1])),
    by_quality_issue: Object.fromEntries(Object.entries(byIssue).sort((a, b) => b[1] - a[1])),
  };
}
