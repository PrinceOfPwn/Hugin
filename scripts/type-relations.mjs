/**
 * type-relations.mjs
 *
 * Classify semantic similarity edges into typed relations (chains_to,
 * alternative_to, counters, requires, enables, related, none).
 *
 * Reads:
 *   src/generated/entities.json
 *   src/generated/similarity.json
 *   src/generated/curated-relations.json     (skip pairs already curated)
 *   data/enriched/.state.json
 *
 * Appends:
 *   data/enriched/relations/typed.jsonl      one line per typed pair
 *   data/enriched/.state.json                { relations: { "src:tgt": pair_hash } }
 *
 * Usage:
 *   node scripts/type-relations.mjs [--min-score 0.80] [--tier S,A] [--changed-only] [--force] [--limit N]
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const MODEL_ID    = "onnx-community/Qwen3-4B-Instruct-2507-ONNX";
const MODEL_DTYPE = "q4";
const MODEL_CACHE = path.resolve(process.env.HUGIN_MODEL_CACHE ?? ".hf-cache");
const MAX_NEW_TOKENS = 160;

const GEN_DIR       = path.resolve("src/generated");
const OUT_FILE      = path.resolve("data/enriched/relations/typed.jsonl");
const STATE_FILE    = path.resolve("data/enriched/.state.json");
const ENTITIES_FILE = path.join(GEN_DIR, "entities.json");
const SIMILAR_FILE  = path.join(GEN_DIR, "similarity.json");
const CURATED_FILE  = path.join(GEN_DIR, "curated-relations.json");

// ── Args ──────────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const val  = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };

const MIN_SCORE    = Number(val("--min-score") || "0.80");
const TIERS        = (val("--tier") || "S,A").split(",").map((t) => t.trim().toUpperCase()).filter(Boolean);
const CHANGED_ONLY = flag("--changed-only");
const FORCE        = flag("--force");
const LIMIT        = Number(val("--limit") || Infinity);

console.log(`type-relations.mjs
  model:         ${MODEL_ID}
  min-score:     ${MIN_SCORE}
  tier filter:   ${TIERS.join(",")}
  changed-only:  ${CHANGED_ONLY}
  force:         ${FORCE}
  limit:         ${LIMIT === Infinity ? "∞" : LIMIT}
`);

// ── Helpers ───────────────────────────────────────────────────────────────────
const sha256 = (v) => crypto.createHash("sha256").update(String(v)).digest("hex");
function readJson(p, fb = null) { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return fb; } }
function writeJson(p, o) { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, JSON.stringify(o, null, 2)); }
function truncate(s, m) { const t = String(s ?? "").replace(/\s+/g, " ").trim(); return t.length <= m ? t : `${t.slice(0, m)}…`; }

// Strip inline YAML metadata from raw summaries so the model doesn't imitate it.
const _META_RE = /\b(?:id|name|category|tier|mitre|analyzed_by|analysis_date|confidence|requires|enables|vault_references|implements|min_windows|needs_admin|tags):\s*(?:\[[^\]]*\]|"[^"]*"|'[^']*'|\S+)/gi;
function cleanForPrompt(s) {
  return String(s ?? "")
    .replace(_META_RE, "")
    .replace(/\bfile:\s*\S+/gi, "")
    .replace(/\bkey_(?:functions|structs|constants):\s*[^\n\r]*/gi, "")
    .replace(/L\d+-L\d+:[^\n\r]*/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

// ── Load data ────────────────────────────────────────────────────────────────
const entities  = readJson(ENTITIES_FILE, []);
const similarity = readJson(SIMILAR_FILE, []);
const curated   = readJson(CURATED_FILE, []);
const state     = readJson(STATE_FILE, { entities: {}, relations: {} });
state.relations = state.relations || {};

const byId = new Map(entities.map((e) => [e.id, e]));

// Existing curated pairs — skip (both directions)
const curatedPairKey = (a, b) => a < b ? `${a}|${b}` : `${b}|${a}`;
const curatedPairs = new Set(curated.map((r) => curatedPairKey(r.source, r.target)));

// ── Filter candidate pairs ────────────────────────────────────────────────────
function tierOK(entity) {
  const t = String(entity?.tier || "").toUpperCase().trim();
  return TIERS.includes(t);
}
function pairHash(a, b) {
  const A = byId.get(a);
  const B = byId.get(b);
  return sha256(JSON.stringify({
    a: A?.title, as: A?.summary,
    b: B?.title, bs: B?.summary,
    model: MODEL_ID,
    prompt_v: 1,
  }));
}

const seen = new Set();  // dedupe (src,tgt) unordered
const candidates = [];
for (const edge of similarity) {
  if (edge.score < MIN_SCORE) continue;
  const A = byId.get(edge.source);
  const B = byId.get(edge.target);
  if (!A || !B) continue;
  if (!tierOK(A) || !tierOK(B)) continue;

  const key = curatedPairKey(edge.source, edge.target);
  if (seen.has(key)) continue;
  seen.add(key);
  if (curatedPairs.has(key)) continue;  // already curated, skip

  const hash = pairHash(edge.source, edge.target);
  const prev = state.relations[key];
  if (CHANGED_ONLY && !FORCE && prev === hash) continue;

  candidates.push({ src: edge.source, tgt: edge.target, score: edge.score, key, hash });
  if (candidates.length >= LIMIT) break;
}

console.log(`Candidate pairs in scope: ${candidates.length}\n`);
if (candidates.length === 0) { console.log("Nothing to type. Exiting."); process.exit(0); }

// ── Prompt ────────────────────────────────────────────────────────────────────
const SYSTEM = `You classify semantic edges in an offensive-security knowledge graph.

Given two cards A and B, decide the most specific relation type from this closed set:
- "chains_to"      — A leads naturally to B in an attack chain (A→B temporal/logical)
- "alternative_to" — A and B achieve the same goal by different means (symmetric)
- "counters"       — A detects or mitigates B (defense→offense, directional)
- "requires"       — B is a prerequisite for A (directional)
- "enables"        — A creates a condition B needs (directional)
- "related"        — semantically close but no specific relation applies (symmetric)
- "none"           — no meaningful relation despite embedding similarity

OUTPUT: {"type":"<one>","reverse":true|false,"confidence":1|2|3|4|5,"rationale":"1 sentence"}

DIRECTION:
- For directional types (chains_to/counters/requires/enables) the schema means A→B.
- If the correct direction is B→A, set "reverse":true.
- For symmetric types (alternative_to/related/none), "reverse" MUST be false.

RULES:
- Prefer "related" over "none" if in doubt; use "none" only for clear misses.
- confidence ≤ 3 → default to "related" unless the specific relation is very clear.
- ONE JSON object. No markdown fences. No prose.

EXAMPLE 1:
A: "SysWhispers2 direct syscall" — resolves SSNs and issues SYSCALL bypassing user-mode hooks
B: "Hell's Gate" — dynamic SSN resolution via ntdll parsing
OUTPUT: {"type":"alternative_to","reverse":false,"confidence":4,"rationale":"Both resolve SSNs at runtime for direct syscalls; different resolution techniques."}

EXAMPLE 2:
A: "Kernel callback ETW-TI filtering rule" — filters Microsoft-Windows-Threat-Intelligence syscall events
B: "Direct syscall via NtCreateThreadEx" — allocates and runs code in remote process using direct kernel transitions
OUTPUT: {"type":"counters","reverse":false,"confidence":5,"rationale":"A is a detection rule that flags the exact syscall pattern used by B."}

EXAMPLE 3:
A: "Load and execute shellcode via VirtualAlloc + CreateThread"
B: "Reflective DLL injection primitive"
OUTPUT: {"type":"requires","reverse":true,"confidence":4,"rationale":"B is a higher-level primitive that depends on the memory-and-thread pattern in A, so A→B is 'enables' but B→A is 'requires'; direction reversed to record as requires."}`;

function buildMessages(src, tgt) {
  const A = byId.get(src);
  const B = byId.get(tgt);
  const user =
    `A:\n  id: ${A.id}\n  title: ${truncate(A.title, 100)}\n  summary: ${truncate(cleanForPrompt(A.summary), 400)}\n\n` +
    `B:\n  id: ${B.id}\n  title: ${truncate(B.title, 100)}\n  summary: ${truncate(cleanForPrompt(B.summary), 400)}`;
  return [
    { role: "system", content: SYSTEM },
    { role: "user",   content: user },
  ];
}

const VALID_TYPES = new Set(["chains_to","alternative_to","counters","requires","enables","related","none"]);
const SYMMETRIC   = new Set(["alternative_to","related","none"]);
const RANGE = (v) => Number.isInteger(v) && v >= 1 && v <= 5 ? v : null;

function parseOutput(raw) {
  const text = String(raw ?? "").trim()
    .replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
  let parsed;
  try { parsed = JSON.parse(text); }
  catch {
    const m = text.match(/\{[\s\S]*\}/);
    if (!m) return null;
    try { parsed = JSON.parse(m[0]); } catch { return null; }
  }
  const type       = String(parsed.type || "").trim();
  const confidence = RANGE(parsed.confidence);
  const rationale  = String(parsed.rationale || "").trim().slice(0, 240);
  if (!VALID_TYPES.has(type) || confidence == null) return null;
  // Force reverse=false for symmetric types even if the model returned true.
  const reverse = SYMMETRIC.has(type) ? false : Boolean(parsed.reverse);
  return { type, reverse, confidence, rationale };
}

// ── Load model ────────────────────────────────────────────────────────────────
console.log(`Loading ${MODEL_ID} (dtype=${MODEL_DTYPE}) from ${MODEL_CACHE}...`);
const { env, pipeline } = await import("@huggingface/transformers");
env.cacheDir = MODEL_CACHE;
env.useFSCache = true;
env.allowRemoteModels = true;
const generator = await pipeline("text-generation", MODEL_ID, { dtype: MODEL_DTYPE });
console.log("Model loaded.\n");

// ── Loop ──────────────────────────────────────────────────────────────────────
fs.mkdirSync(path.dirname(OUT_FILE), { recursive: true });
const out = fs.createWriteStream(OUT_FILE, { flags: "a" });

let ok = 0, fail = 0;
const dist = {};
const t0 = Date.now();

// Graceful shutdown
let shuttingDown = false;
for (const sig of ["SIGTERM", "SIGINT"]) {
  process.on(sig, () => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n${sig} received — flushing state before exit`);
    try { out.end(); writeJson(STATE_FILE, state); } catch { /* ignore */ }
    process.exit(130);
  });
}

for (let i = 0; i < candidates.length; i++) {
  const c = candidates[i];
  const label = `[${i + 1}/${candidates.length}] ${c.src} ↔ ${c.tgt} (sim=${c.score.toFixed(3)})`;
  process.stdout.write(`${label} … `);

  try {
    const result = await generator(buildMessages(c.src, c.tgt), {
      max_new_tokens:      MAX_NEW_TOKENS,
      do_sample:           false,
      temperature:         1.0,
      repetition_penalty:  1.1,
      chat_template_kwargs: { enable_thinking: false },
    });
    const gen = result?.[0]?.generated_text;
    const last = Array.isArray(gen) ? gen.at(-1)?.content : String(gen ?? "");
    const parsed = parseOutput(last);
    if (!parsed) throw new Error("unparseable");

    const rec = {
      src: c.src, tgt: c.tgt, similarity: c.score,
      ...parsed,
      _model: MODEL_ID, _dtype: MODEL_DTYPE,
      _at: new Date().toISOString(),
      _hash: c.hash,
    };
    out.write(JSON.stringify(rec) + "\n");
    state.relations[c.key] = c.hash;
    dist[parsed.type] = (dist[parsed.type] || 0) + 1;
    ok++;
    const arrow = parsed.reverse ? "←" : "→";
    console.log(`✓ ${parsed.type} ${arrow} conf=${parsed.confidence}`);
  } catch (err) {
    fail++;
    console.log(`✗ ${err.message}`);
  }

  if ((i + 1) % 50 === 0) writeJson(STATE_FILE, state);
}

out.end();
writeJson(STATE_FILE, state);
try { await generator.dispose?.(); } catch { /* ignore */ }

const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
console.log(`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Relation typing complete in ${elapsed}s
   OK:      ${ok}
   Failed:  ${fail}
   Type distribution:
${Object.entries(dist).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`     ${k.padEnd(16)} ${v}`).join("\n")}
   Out:     ${OUT_FILE}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`);
