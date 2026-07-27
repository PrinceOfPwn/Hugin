/**
 * detect-format.mjs
 *
 * Given a JSONL file of unknown shape, ask Qwen3-4B-Instruct-2507 to inspect
 * a small sample and produce a mapping spec that reshapes each record into
 * the canonical schema expected by scripts/normalize-samples.mjs.
 *
 * The LLM output is DATA, not code — we never eval anything it returns.
 *
 * Input:
 *   data/incoming/<name>.jsonl
 *
 * Output:
 *   data/incoming/<name>.mapping.json    (committed alongside the input)
 *
 * Usage:
 *   node scripts/detect-format.mjs data/incoming/foo.jsonl [--force]
 */

import fs from "node:fs";
import path from "node:path";

const MODEL_ID    = process.env.HUGIN_DETECT_MODEL ?? "onnx-community/gemma-4-E2B-it-ONNX";
const MODEL_DTYPE = "q4";
const MODEL_CACHE = path.resolve(process.env.HUGIN_MODEL_CACHE ?? ".hf-cache");
const MAX_NEW_TOKENS = 350;
const SAMPLE_SIZE = 3;

const args = process.argv.slice(2);
const input = args.find((a) => !a.startsWith("--"));
const force = args.includes("--force");

if (!input) {
  console.error("Usage: node scripts/detect-format.mjs <input.jsonl> [--force]");
  process.exit(1);
}
let INPUT   = path.resolve(input);
let MAPPING = INPUT.replace(/\.jsonl$/i, ".mapping.json");

if (!fs.existsSync(INPUT)) { console.error(`Not found: ${INPUT}`); process.exit(1); }

// Auto-wrap non-JSONL files (e.g. .py, .md, .c, .go) into a single-line JSONL
if (!INPUT.endsWith(".jsonl")) {
  const rawText = fs.readFileSync(INPUT, "utf8");
  const wrapper = {
    source_file: path.basename(INPUT),
    content: rawText,
    file_type: INPUT.split(".").pop()
  };
  const jsonlPath = INPUT + ".jsonl";
  fs.writeFileSync(jsonlPath, JSON.stringify(wrapper) + "\n");
  console.log(`Wrapped non-JSONL file into ${jsonlPath}`);
  INPUT = jsonlPath;
  MAPPING = INPUT.replace(/\.jsonl$/i, ".mapping.json");
}

if (fs.existsSync(MAPPING) && !force) {
  const inputMtime = fs.statSync(INPUT).mtimeMs;
  const mappingMtime = fs.statSync(MAPPING).mtimeMs;
  if (inputMtime <= mappingMtime) {
    console.log(`Mapping already exists and is up to date (${MAPPING}). Use --force to regenerate.`);
    process.exit(0);
  }
  console.log(`Input file is newer than mapping (${MAPPING}). Regenerating mapping with LLM...`);
}

// ── Sample the input ─────────────────────────────────────────────────────────
const raw = fs.readFileSync(INPUT, "utf8");
const allLines = raw.split("\n").filter(Boolean);
const sampleLines = allLines.slice(0, SAMPLE_SIZE);

const samples = [];
for (const line of sampleLines) {
  try { samples.push(JSON.parse(line)); }
  catch { /* skip malformed */ }
}
if (samples.length === 0) {
  console.error(`No parseable JSON records in first ${SAMPLE_SIZE} lines.`);
  process.exit(1);
}
console.log(`Sampled ${samples.length} records from ${allLines.length} total in ${path.basename(INPUT)}`);

// ── System Prompt del Clasificador Universal y Generador de Grafos ──────────
const SYSTEM = `You are a universal data-ingestion and knowledge-graph classifier for the HUGIN offensive-security vault.

TASK: Read N sample records from a JSONL file. The input can contain ANY format: Q&A pairs, raw source code, markdown notes, playbooks, or offensive security traces.
Return a JSON mapping-spec that tells our normalizer how to extract data, map it to the canonical schema, AND extract graph entities/relations.

CANONICAL TARGET SCHEMA:
  id           string — stable unique record id
  prompt       string — context / title / scenario / question
  answer       string — main technical payload / code / assessment / narrative / notes
  category     string — MUST be mapped to standard MITRE ATT&CK tactic (e.g. recon, initial_access, execution, persistence, privilege_escalation, defense_evasion, credential_access, discovery, lateral_movement, collection, c2, exfiltration, impact)
  tags         string[] — free-text tags
  kind         string — one of: technique, tradecraft_qa, chain, detection, concept, lgtm_note, playbook, source, documentation, source_code, markdown_notes
  entities     array  — extracted MITRE TTPs (e.g. T1055), tools (e.g. Cobalt Strike), or concepts.

OUTPUT — return EXACTLY this JSON shape, nothing else:

{
  "source_name":  string,
  "confidence":   1|2|3|4|5,
  "record_shape": "flat" | "nested" | "raw_text" | "code_block",
  "detected_language": string, // e.g. "en", "es", "raw_code"
  "field_map": {
    "id":       string | null,          // JSONPath to unique ID
    "prompt":   string | null,          // JSONPath to context/title
    "answer":   string | null,          // JSONPath to main text/code body
    "category": string | null,          // JSONPath to topic (will be normalized to MITRE)
    "tags":     string | null           // JSONPath ending in [*] for arrays
  },
  "constants": {
    "kind":         string,             // e.g. "source_code" if it's code, "tradecraft_qa" if Q&A
    "category":     string,             // Fallback MITRE category
    "publishState": "core" | "support"
  },
  "graph_extraction": {
    "entities": [
      {
        "type": "MITRE_TTP" | "Tool" | "Primitive",
        "extraction_method": "regex" | "jsonpath",
        "pattern": string               // e.g. "\\bT\\d{4}(?:\\.\\d{3})?\\b" or "$.tools_used[*]"
      }
    ],
    "relations": [
      {
        "type": "uses" | "bypasses" | "mitigates" | "depends_on",
        "extraction_method": "regex" | "constant",
        "pattern": string               // e.g. "bypasses (.*?)" or fixed relation
      }
    ]
  },
  "id_strategy":  "field" | "hash",
  "notes":        string
}

RULES:
- UNIVERSAL INPUT: If the input is raw code, map the entire code block to "answer" and set "kind" to "source_code". If it's markdown notes, set "kind" to "markdown_notes".
- MULTILINGUAL: If the content is in Spanish or another language, set "detected_language". The normalizer will handle standardizing the category to English MITRE tactics.
- GRAPH EXTRACTION: Provide regex patterns to extract entities (like TTPs, tool names) directly from the mapped "answer" text. This allows fast extraction without calling an LLM per record.
- Return ONE JSON object. No markdown fences. No prose.`;

function smartTrim(obj, maxStrLen = 120) {
  if (obj == null) return obj;
  if (typeof obj === "string") {
    return obj.length > maxStrLen ? `${obj.slice(0, maxStrLen)}…` : obj;
  }
  if (Array.isArray(obj)) {
    return obj.slice(0, 3).map((item) => smartTrim(item, maxStrLen));
  }
  if (typeof obj === "object") {
    const res = {};
    for (const [k, v] of Object.entries(obj)) {
      res[k] = smartTrim(v, maxStrLen);
    }
    return res;
  }
  return obj;
}

const userMsg = `SAMPLE RECORDS (${samples.length}):\n` +
  samples.map((r, i) => `[${i + 1}] ${JSON.stringify(smartTrim(r))}`).join("\n");

console.log(`Loading ${MODEL_ID} (dtype=${MODEL_DTYPE})…`);
const { env, pipeline } = await import("@huggingface/transformers");
env.cacheDir = MODEL_CACHE;
env.useFSCache = true;
env.allowRemoteModels = true;

const generator = await pipeline("text-generation", MODEL_ID, { dtype: MODEL_DTYPE });
console.log("Model loaded. Requesting mapping…");

const t0 = Date.now();
let mappingRaw;
try {
  const result = await generator([
    { role: "system", content: SYSTEM },
    { role: "user",   content: userMsg },
  ], {
    max_new_tokens:      MAX_NEW_TOKENS,
    do_sample:           false,
    temperature:         1.0,
    repetition_penalty:  1.1,
    chat_template_kwargs: { enable_thinking: false },
  });
  const gen = result?.[0]?.generated_text;
  mappingRaw = Array.isArray(gen) ? gen.at(-1)?.content : String(gen ?? "");
} finally {
  try { await generator.dispose?.(); } catch {}
}

const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
console.log(`Model response in ${elapsed}s (${(mappingRaw ?? "").length} chars)`);

// ── Parse and validate ───────────────────────────────────────────────────────
const cleaned = String(mappingRaw ?? "").trim()
  .replace(/^```(?:json)?\s*/i, "")
  .replace(/\s*```$/, "")
  .trim();

let parsed;
try { parsed = JSON.parse(cleaned); }
catch {
  const m = cleaned.match(/\{[\s\S]*\}/);
  if (!m) { console.error("Could not extract JSON from model output. Raw:"); console.error(cleaned.slice(0, 1000)); process.exit(1); }
  parsed = JSON.parse(m[0]);
}

// Validation
const validKinds = new Set(["tradecraft_qa","technique","chain","detection","concept","lgtm_note","playbook","source","documentation","source_code","markdown_notes"]);
const errors = [];
if (typeof parsed.source_name !== "string" || !parsed.source_name)                errors.push("source_name missing");
if (!Number.isInteger(parsed.confidence) || parsed.confidence < 1 || parsed.confidence > 5) errors.push("confidence out of range");
if (!parsed.field_map || typeof parsed.field_map !== "object")                    errors.push("field_map missing");
if (parsed.field_map && typeof parsed.field_map.answer !== "string" && parsed.field_map.answer !== null) errors.push("field_map.answer must be jsonpath or null");
if (!parsed.constants || !validKinds.has(parsed.constants?.kind))                 errors.push(`constants.kind must be one of ${[...validKinds].join("|")}`);
if (!["field","hash"].includes(parsed.id_strategy))                               errors.push("id_strategy must be field|hash");

if (errors.length) {
  console.error("Mapping failed validation:");
  errors.forEach((e) => console.error(`  ✗ ${e}`));
  console.error("Raw model output:");
  console.error(cleaned);
  process.exit(1);
}

// Attach provenance for auditability
parsed._detected = {
  input:            path.relative(process.cwd(), INPUT),
  input_records:    allLines.length,
  sample_size:      samples.length,
  model:            MODEL_ID,
  detected_at:      new Date().toISOString(),
  elapsed_seconds:  Number(elapsed),
};

fs.writeFileSync(MAPPING, JSON.stringify(parsed, null, 2));
console.log(`\nMapping saved: ${MAPPING}`);
console.log(`  source_name : ${parsed.source_name}`);
console.log(`  confidence  : ${parsed.confidence}/5`);
console.log(`  kind        : ${parsed.constants.kind}`);
console.log(`  id_strategy : ${parsed.id_strategy}`);
if (parsed.confidence < 3) {
  console.log(`\n⚠ Low confidence — file will be quarantined by apply-mapping.mjs`);
}
