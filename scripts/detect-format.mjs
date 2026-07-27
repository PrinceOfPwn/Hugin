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

const MODEL_ID    = process.env.HUGIN_DETECT_MODEL ?? "onnx-community/Qwen2.5-1.5B-Instruct";
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
const INPUT   = path.resolve(input);
const MAPPING = INPUT.replace(/\.jsonl$/i, ".mapping.json");

if (!fs.existsSync(INPUT)) { console.error(`Not found: ${INPUT}`); process.exit(1); }
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

// ── Prompt ───────────────────────────────────────────────────────────────────
const SYSTEM = `You are a universal data-ingestion classifier for the HUGIN offensive-security knowledge vault.

TASK: Read N sample records from a JSONL file. The input file can contain ANY type of offensive security data:
- Q&A pairs / training material
- Offensive security techniques / tradecraft (e.g. exploit validation, attack steps, blackboard traces, worker results)
- Playbooks / detections / chains / technical documentation

Return a JSON mapping-spec that tells our normalizer how to extract and reshape every record into the canonical schema.

CANONICAL TARGET SCHEMA (fields the normalizer expects):
  id           string — stable unique record id (e.g. $.unit_id, $.id, $.uuid)
  prompt       string — context / title / scenario / role / question / unit_id
  answer       string — main technical payload / assessment / narrative / execution details / solution / body
  category     string — one of: recon, initial_access, execution, persistence,
                        privilege_escalation, defense_evasion, credential_access,
                        discovery, lateral_movement, collection, c2, exfiltration,
                        impact, tools, internals, evasion, unknown
  tags         string[] — free-text tags or primitives (e.g. $.sample.worker_result.primitives_present[*])
  kind         string — one of: technique, tradecraft_qa, chain, detection,
                        concept, lgtm_note, playbook, source, documentation

OUTPUT — return EXACTLY this JSON shape, nothing else:

{
  "source_name":  string,               // descriptive name (e.g. "offx-blackboard-validation")
  "confidence":   1|2|3|4|5,            // your confidence in the mapping
  "record_shape": "flat" | "nested",
  "field_map": {
    "id":       string | null,          // JSONPath expression to unique ID (e.g. "$.unit_id")
    "prompt":   string | null,          // JSONPath to context/scenario/prompt (e.g. "$.role" or "$.unit_id")
    "answer":   string | null,          // JSONPath to main text/assessment (e.g. "$.sample.worker_result.assessment")
    "category": string | null,          // JSONPath to category/topic (e.g. "$.meta.primary_topic")
    "tags":     string | null,          // JSONPath ending in [*] for arrays
    "source":   string | null           // JSONPath to source/provider
  },
  "constants": {                        // fields to set unconditionally on every record
    "kind":         string,             // "technique" if offensive security data/sample/blackboard, else "tradecraft_qa"
    "category":     string,             // fallback category
    "publishState": "core" | "support"
  },
  "id_strategy":  "field" | "hash",     // "field" if id exists, "hash" if null
  "notes":        string
}

RULES:
- JSONPath dialect: "$" is root, "." for child, "[N]" for index, "[*]" for wildcard.
  Examples for nested structures: "$.unit_id", "$.sample.worker_result.assessment", "$.meta.primary_topic"
- For nested structures (like blackboard candidates, worker results, evaluation traces), map "answer" to the deepest technical text field (e.g. "$.sample.worker_result.assessment" or "$.sample.blackboard_patch.facts[0].text").
- Set "kind" in constants to "technique" if the input is a technique/exploit/attack record, or "tradecraft_qa" if Q&A.
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
const validKinds = new Set(["tradecraft_qa","technique","chain","detection","concept","lgtm_note","playbook","source","documentation"]);
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
