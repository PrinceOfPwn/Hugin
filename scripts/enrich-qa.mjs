/**
 * enrich-qa.mjs
 *
 * Reads a raw Q&A .jsonl file and enriches each record with:
 *   - _hugin.summary  : 2-sentence technical summary (Qwen3-4B)
 *   - _hugin.mitre    : MITRE ATT&CK TTP IDs (Qwen3-4B)
 *   - _hugin.tags     : Key technical primitives / APIs (Qwen3-4B)
 *
 * Model: onnx-community/Qwen3-4B  (q4, ~2.4 GB RAM peak)
 * Runtime: @huggingface/transformers  — 100% Node.js, no Ollama, no API keys.
 *
 * Usage:
 *   node scripts/enrich-qa.mjs <input.jsonl> <output.jsonl>
 *   node scripts/enrich-qa.mjs <input.jsonl> <output.jsonl> --resume
 *
 * Flags:
 *   --resume   Skip records whose id already appears in <output.jsonl>
 *              (safe to rerun after a partial failure)
 *
 * After this completes, run:
 *   node scripts/import-qa.mjs <output.jsonl>
 *   npm run data:build && npm run data:validate
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// ── Config ────────────────────────────────────────────────────────────────────
const MODEL_ID = "onnx-community/Qwen3-4B";
const MODEL_DTYPE = "q4";
const MODEL_CACHE = path.resolve(process.env.HUGIN_MODEL_CACHE ?? ".hf-cache");

// Max new tokens the model generates per record
const MAX_NEW_TOKENS = 256;

// ── Args ──────────────────────────────────────────────────────────────────────
const positional = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const flags = new Set(process.argv.slice(2).filter((a) => a.startsWith("--")));
const RESUME = flags.has("--resume");

if (positional.length < 2) {
  console.error("Usage: node scripts/enrich-qa.mjs <input.jsonl> <output.jsonl> [--resume]");
  process.exit(1);
}

const inputPath = path.resolve(positional[0]);
const outputPath = path.resolve(positional[1]);

if (!fs.existsSync(inputPath)) {
  console.error(`Input file not found: ${inputPath}`);
  process.exit(1);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const sha256 = (v) => crypto.createHash("sha256").update(String(v)).digest("hex");

function truncate(text, maxChars) {
  if (!text) return "";
  const t = String(text).replace(/\s+/g, " ").trim();
  return t.length <= maxChars ? t : `${t.slice(0, maxChars)}…`;
}

/**
 * Build the prompt sent to Qwen3-4B.
 * We pass the full scenario (prompt) and the full answer, truncated to stay
 * within the context window. The model must return strict JSON only.
 */
function buildPrompt(record) {
  const scenario = truncate(record.prompt ?? "", 1200);
  const answer   = truncate(record.answer  ?? "", 1800);

  return [
    {
      role: "system",
      content:
        "You are a senior offensive-security analyst. " +
        "Your task is to read a technical Q&A record and extract structured metadata. " +
        "You MUST reply with a single JSON object and nothing else — no markdown fences, no explanation. " +
        "The JSON must have exactly these three keys:\n" +
        '  "summary" : string — A precise 1-2 sentence technical summary of the core finding or technique. ' +
        "Write in third-person, past tense, focusing on the security-relevant mechanism. " +
        "Do NOT start with 'The question' or 'This record'.\n" +
        '  "mitre"   : string[] — MITRE ATT&CK technique IDs that apply (e.g. ["T1055","T1106"]). ' +
        "Use sub-technique notation when precise (e.g. T1055.002). Return [] if none apply clearly.\n" +
        '  "tags"    : string[] — Up to 8 lowercase technical keywords, API names, or primitives ' +
        "(e.g. [\"memcpy\",\"seh\",\"windbg\",\"apc\"]). Avoid generic words like 'exploit' or 'vulnerability'.",
    },
    {
      role: "user",
      content:
        `SCENARIO:\n${scenario}\n\n` +
        `FULL TECHNICAL ANSWER:\n${answer}`,
    },
  ];
}

/**
 * Parse the raw model output into { summary, mitre, tags }.
 * Falls back gracefully if the model returns malformed JSON.
 */
function parseModelOutput(raw, record) {
  const text = String(raw ?? "").trim();

  // Strip accidental markdown fences
  const stripped = text
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/, "")
    .trim();

  try {
    const parsed = JSON.parse(stripped);
    return {
      summary: typeof parsed.summary === "string" ? parsed.summary.trim() : "",
      mitre:   Array.isArray(parsed.mitre) ? parsed.mitre.map(String).filter(Boolean) : [],
      tags:    Array.isArray(parsed.tags)  ? parsed.tags.map(String).filter(Boolean)  : [],
    };
  } catch {
    // Fallback: extract fields with regex
    const summaryM = stripped.match(/"summary"\s*:\s*"([^"]+)"/);
    const mitreM   = stripped.match(/"mitre"\s*:\s*\[([^\]]*)\]/);
    const tagsM    = stripped.match(/"tags"\s*:\s*\[([^\]]*)\]/);

    const parseList = (str) =>
      str ? str.match(/"([^"]+)"/g)?.map((s) => s.replace(/"/g, "")) ?? [] : [];

    console.warn(`  ⚠ JSON parse failed for record ${record.id ?? "?"}, using regex fallback.`);
    return {
      summary: summaryM ? summaryM[1].trim() : "",
      mitre:   parseList(mitreM?.[1]),
      tags:    parseList(tagsM?.[1]),
    };
  }
}

// ── Load already-enriched IDs (resume support) ────────────────────────────────
const doneIds = new Set();
if (RESUME && fs.existsSync(outputPath)) {
  for (const line of fs.readFileSync(outputPath, "utf8").split("\n").filter(Boolean)) {
    try {
      const r = JSON.parse(line);
      if (r.id) doneIds.add(r.id);
    } catch { /* ignore */ }
  }
  console.log(`--resume: ${doneIds.size} already-enriched records will be skipped.`);
}

// ── Read input ────────────────────────────────────────────────────────────────
const rawLines = fs.readFileSync(inputPath, "utf8").split("\n").filter(Boolean);
const records  = rawLines
  .map((line, i) => {
    try { return JSON.parse(line); }
    catch { console.warn(`Line ${i + 1}: parse error, skipping.`); return null; }
  })
  .filter(Boolean);

const toEnrich = records.filter((r) => !doneIds.has(r.id));
console.log(`Records total: ${records.length}  |  To enrich: ${toEnrich.length}`);

if (toEnrich.length === 0) {
  console.log("Nothing to enrich. Exiting.");
  process.exit(0);
}

// ── Load model ────────────────────────────────────────────────────────────────
console.log(`\nLoading ${MODEL_ID} (dtype=${MODEL_DTYPE}) from cache: ${MODEL_CACHE}`);
console.log("This may take 1-2 minutes on first run (model download ~2.4 GB)...\n");

const { env, pipeline } = await import("@huggingface/transformers");
env.cacheDir        = MODEL_CACHE;
env.useFSCache      = true;
env.allowRemoteModels = true;

const generator = await pipeline("text-generation", MODEL_ID, {
  dtype: MODEL_DTYPE,
  // Qwen3 supports thinking mode; disable it for deterministic JSON output
  // by setting the generation config below
});

console.log("Model loaded.\n");

// ── Output stream ─────────────────────────────────────────────────────────────
// Open in append mode so --resume works correctly
const out = fs.createWriteStream(outputPath, { flags: RESUME ? "a" : "w" });

// Also write already-done records back if NOT resuming (fresh run)
if (!RESUME) {
  for (const r of records.filter((r) => doneIds.has(r.id))) {
    out.write(JSON.stringify(r) + "\n");
  }
}

// ── Enrich loop ───────────────────────────────────────────────────────────────
let success = 0;
let failed  = 0;

for (let i = 0; i < toEnrich.length; i++) {
  const record  = toEnrich[i];
  const ordinal = `[${i + 1}/${toEnrich.length}]`;
  const recId   = record.id ?? sha256(record.prompt ?? "").slice(0, 16);

  process.stdout.write(`${ordinal} Enriching ${recId}… `);

  try {
    const messages = buildPrompt(record);

    const result = await generator(messages, {
      max_new_tokens:      MAX_NEW_TOKENS,
      do_sample:           false,         // greedy — deterministic JSON
      temperature:         1.0,           // required when do_sample=false
      repetition_penalty:  1.1,
      // Qwen3 "thinking" mode off: no <think> tags in output
      chat_template_kwargs: { enable_thinking: false },
    });

    // transformers.js returns array of {generated_text: [{role, content}]}
    const generated = result?.[0]?.generated_text;
    const lastMsg   = Array.isArray(generated) ? generated.at(-1)?.content : String(generated ?? "");

    const enriched = parseModelOutput(lastMsg, record);

    const outputRecord = {
      ...record,
      _hugin: {
        summary: enriched.summary,
        mitre:   enriched.mitre,
        tags:    enriched.tags,
        model:   MODEL_ID,
        dtype:   MODEL_DTYPE,
        enrichedAt: new Date().toISOString(),
      },
    };

    out.write(JSON.stringify(outputRecord) + "\n");
    success++;
    console.log(`✓  ${enriched.mitre.length} TTPs  |  "${enriched.summary.slice(0, 60)}…"`);
  } catch (err) {
    console.log(`✗  ERROR: ${err.message}`);
    // Write original record unchanged so import-qa still picks it up
    out.write(JSON.stringify({ ...record, _hugin: { error: err.message } }) + "\n");
    failed++;
  }
}

out.end();
await generator.dispose?.();

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Enrichment complete
 Success : ${success}
 Failed  : ${failed}
 Output  : ${outputPath}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Next steps:
  node scripts/import-qa.mjs ${path.relative(process.cwd(), outputPath)}
  npm run data:build && npm run data:validate
`);
