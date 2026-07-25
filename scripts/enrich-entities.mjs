/**
 * enrich-entities.mjs
 *
 * Enrich core entities with LLM-generated metadata for the HUGIN knowledge graph.
 *
 * Model: onnx-community/Qwen3-4B-Instruct-2507-ONNX (q4)
 * Runtime: @huggingface/transformers — 100% Node, no API.
 *
 * Reads:
 *   src/generated/entities.json
 *   src/generated/curated-relations.json    (for neighbors)
 *   src/generated/similarity.json           (fallback neighbors)
 *   data/enriched/.state.json               (cache invalidation)
 *
 * Writes:
 *   data/enriched/entities/<id>.json        (one file per enriched entity)
 *   data/enriched/.state.json               (updated content hashes)
 *
 * Usage:
 *   node scripts/enrich-entities.mjs [--tier S,A] [--changed-only] [--force] [--limit N]
 *
 * Flags:
 *   --tier S,A       Only enrich entities whose tier is in this comma list
 *   --changed-only   Skip entities whose content hash matches .state.json
 *   --force          Ignore cache and re-enrich everything in scope
 *   --limit N        Stop after N entities (for smoke tests)
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const MODEL_ID    = "onnx-community/Qwen3-4B-Instruct-2507-ONNX";
const MODEL_DTYPE = "q4";
const MODEL_CACHE = path.resolve(process.env.HUGIN_MODEL_CACHE ?? ".hf-cache");
const MAX_NEW_TOKENS = 512;

const GEN_DIR       = path.resolve("src/generated");
const OUT_DIR       = path.resolve("data/enriched/entities");
const STATE_FILE    = path.resolve("data/enriched/.state.json");
const ENTITIES_FILE = path.join(GEN_DIR, "entities.json");
const CURATED_FILE  = path.join(GEN_DIR, "curated-relations.json");
const SIMILAR_FILE  = path.join(GEN_DIR, "similarity.json");

// ── Args ──────────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const val  = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };

const TIERS        = (val("--tier") || "S,A").split(",").map((t) => t.trim().toUpperCase()).filter(Boolean);
const CHANGED_ONLY = flag("--changed-only");
const FORCE        = flag("--force");
const LIMIT        = Number(val("--limit") || Infinity);

console.log(`enrich-entities.mjs
  model:         ${MODEL_ID}
  dtype:         ${MODEL_DTYPE}
  tier filter:   ${TIERS.join(",")}
  changed-only:  ${CHANGED_ONLY}
  force:         ${FORCE}
  limit:         ${LIMIT === Infinity ? "∞" : LIMIT}
`);

// ── Helpers ───────────────────────────────────────────────────────────────────
const sha256 = (v) => crypto.createHash("sha256").update(String(v)).digest("hex");
const short  = (v) => sha256(v).slice(0, 16);

function readJson(p, fallback = null) {
  try { return JSON.parse(fs.readFileSync(p, "utf8")); }
  catch { return fallback; }
}
function writeJson(p, obj) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj, null, 2));
}
function truncate(s, max) {
  const t = String(s ?? "").replace(/\s+/g, " ").trim();
  return t.length <= max ? t : `${t.slice(0, max)}…`;
}

// Strip YAML-style metadata fields that appear inline in some entity summaries
// (id:, tier:, mitre:, file:, key_functions:, L###-L###:, …). We keep this in
// sync with src/lib/summaryParser.ts:cleanBodyMarkdown — it doesn't need to be
// perfect, just clean enough that the model doesn't imitate the raw noise.
const _META_RE = /\b(?:id|name|category|tier|mitre|analyzed_by|analysis_date|confidence|requires|enables|vault_references|implements|min_windows|needs_admin|tags):\s*(?:\[[^\]]*\]|"[^"]*"|'[^']*'|\S+)/gi;
function cleanForPrompt(s) {
  return String(s ?? "")
    .replace(_META_RE, "")
    .replace(/\bfile:\s*\S+/gi, "")
    .replace(/\bkey_(?:functions|structs|constants):\s*[^\n\r]*/gi, "")
    .replace(/L\d+-L\d+:[^\n\r]*/g, "")
    .replace(/\[\s*0x[0-9A-Fa-f, ]+\s*\]/g, "")
    .replace(/^(?:Operator Playbook TL;DR\s*[-—:]?\s*)*/i, "")
    .replace(/\s+/g, " ")
    .trim();
}

// ── Load data ─────────────────────────────────────────────────────────────────
const entities     = readJson(ENTITIES_FILE, []);
const curated      = readJson(CURATED_FILE, []);
const similarity   = readJson(SIMILAR_FILE, []);
const state        = readJson(STATE_FILE, { entities: {}, relations: {} });

console.log(`Loaded: ${entities.length} entities · ${curated.length} curated · ${similarity.length} similarity edges`);

const byId = new Map(entities.map((e) => [e.id, e]));

// ── Build neighbor lookup: prefer curated, fall back to similarity ────────────
const curatedNeighbors = new Map();   // id → Set<string>
for (const r of curated) {
  if (!curatedNeighbors.has(r.source)) curatedNeighbors.set(r.source, new Set());
  if (!curatedNeighbors.has(r.target)) curatedNeighbors.set(r.target, new Set());
  curatedNeighbors.get(r.source).add(r.target);
  curatedNeighbors.get(r.target).add(r.source);
}
const similarNeighbors = new Map();   // id → [{id, score}] sorted desc
for (const r of similarity) {
  if (!similarNeighbors.has(r.source)) similarNeighbors.set(r.source, []);
  similarNeighbors.get(r.source).push({ id: r.target, score: r.score });
}
for (const [, arr] of similarNeighbors) arr.sort((a, b) => b.score - a.score);

const NEIGHBOR_SIM_MIN = 0.55;   // ignore weak similarity neighbors as context

function topNeighbors(entityId, n = 3) {
  const cur = [...(curatedNeighbors.get(entityId) || [])].slice(0, n).map((id) => ({ id, from: "curated" }));
  if (cur.length >= n) return cur;
  const sim = (similarNeighbors.get(entityId) || [])
    .filter((x) => x.score >= NEIGHBOR_SIM_MIN && !cur.find((c) => c.id === x.id))
    .slice(0, n - cur.length)
    .map((x) => ({ id: x.id, from: "similarity", score: x.score }));
  return [...cur, ...sim];
}

// ── Filter candidates ─────────────────────────────────────────────────────────
function tierOf(entity) {
  return String(entity.tier || "").toUpperCase().trim() || null;
}
function contentHash(entity, neighbors) {
  return sha256(JSON.stringify({
    id: entity.id,
    title: entity.title,
    summary: entity.summary,
    body: entity.bodyRef,
    tier: entity.tier,
    mitre: entity.mitre,
    tags: entity.tags?.slice(0, 20),
    n: neighbors.map((x) => x.id),
    model: MODEL_ID,
    prompt_v: 2,
  }));
}

const candidates = [];
for (const entity of entities) {
  if (entity.publishState !== "core") continue;
  const t = tierOf(entity);
  if (!TIERS.includes(t)) continue;
  const neighbors = topNeighbors(entity.id, 3);
  const hash = contentHash(entity, neighbors);
  const prev = state.entities[entity.id];
  const cacheHit = !FORCE && prev === hash;
  if (CHANGED_ONLY && cacheHit) continue;
  candidates.push({ entity, neighbors, hash, cacheHit });
  if (candidates.length >= LIMIT) break;
}

console.log(`Candidates in scope: ${candidates.length} (cache hits skipped: ${CHANGED_ONLY})`);
if (candidates.length === 0) {
  console.log("Nothing to enrich. Exiting.");
  process.exit(0);
}

// ── Build prompt (system + user) ──────────────────────────────────────────────
const SYSTEM = `You are a senior offensive-security analyst enriching a knowledge graph of Windows internals, adversary tradecraft, and detection engineering.

Read ONE card + its top-3 semantic neighbors. Return ONE JSON object matching this schema exactly:
{
  "summary":         string,   // 1-2 sentences, past tense, third-person, mechanism-focused
  "mitre":           string[], // ATT&CK IDs, up to 5, sub-technique OK ("T1055.002")
  "apis":            string[], // exact Win32/NT/kernel API names, up to 10
  "iocs":            string[], // literal strings: paths, section names, syscall names, up to 8
  "tags":            string[], // lowercase primitives, up to 8
  "chains_with":     string[], // neighbor IDs from CONTEXT that naturally follow. MUST come from CONTEXT.
  "alternatives":    string[], // neighbor IDs that achieve same goal differently. MUST come from CONTEXT.
  "counters":        string[], // neighbor IDs that detect/mitigate. MUST come from CONTEXT.
  "stealth":         1|2|3|4|5, // 1=very noisy, 5=in-memory only, no artifacts
  "complexity":      1|2|3|4|5, // 1=trivial, 5=nation-state
  "os_requirements": string,    // e.g. "Win10 1809+, admin optional, x64 only"
  "confidence":      1|2|3|4|5  // your confidence in the classification
}

HARD RULES:
- IDs in chains_with/alternatives/counters MUST exist EXACTLY in the CONTEXT list — never invent.
- If confidence < 3, leave optional arrays empty rather than guess.
- Return ONE JSON object. No markdown fences. No prose.

EXAMPLE:
CARD:
  id: T-014
  title: Direct syscall via SysWhispers2
  summary: Bypass EDR user-mode hooks by resolving SSNs at runtime and issuing SYSCALL directly.
CONTEXT NEIGHBORS:
  T-042: Hell's Gate — dynamic SSN resolution via ntdll parsing
  T-018: Halo's Gate — SSN resolution when a syscall is hooked
  D-007: ETW-TI kernel syscall trace
OUTPUT:
{"summary":"Resolved syscall service numbers at runtime and issued direct kernel transitions, evading user-mode API hooks planted by EDRs.","mitre":["T1106","T1620"],"apis":["NtCreateThreadEx","NtProtectVirtualMemory","NtWriteVirtualMemory"],"iocs":["ntdll!Zw*","stub_direct_syscall"],"tags":["syscall","edr-evasion","ssn-resolution","asm-stubs"],"chains_with":["T-042"],"alternatives":["T-018"],"counters":["D-007"],"stealth":4,"complexity":3,"os_requirements":"Win10+, x64","confidence":5}`;

function buildMessages({ entity, neighbors }) {
  const ctxLines = neighbors.map((n) => {
    const e = byId.get(n.id);
    if (!e) return `  ${n.id}: (unknown)`;
    return `  ${e.id}: ${truncate(e.title, 80)} — ${truncate(cleanForPrompt(e.summary), 140)}`;
  }).join("\n");

  const user =
    `CARD:\n` +
    `  id: ${entity.id}\n` +
    `  title: ${truncate(entity.title, 120)}\n` +
    `  summary: ${truncate(cleanForPrompt(entity.summary), 900)}\n` +
    `  tier: ${entity.tier || "?"}\n` +
    `  category: ${entity.category || "?"}\n` +
    `  mitre_curated: ${(entity.mitre || []).join(", ") || "(none)"}\n` +
    `  tags_curated:  ${(entity.tags || []).slice(0, 8).join(", ") || "(none)"}\n\n` +
    `CONTEXT NEIGHBORS:\n${ctxLines || "  (none)"}`;

  return [
    { role: "system", content: SYSTEM },
    { role: "user",   content: user },
  ];
}

// ── Parse + validate output ───────────────────────────────────────────────────
const RANGE = (v) => Number.isInteger(v) && v >= 1 && v <= 5 ? v : null;
const MITRE_RE = /^T\d{4}(?:\.\d{3})?$/;

function parseModelOutput(raw, entity, allowedNeighborIds) {
  const text = String(raw ?? "").trim()
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/, "")
    .trim();

  let parsed;
  try { parsed = JSON.parse(text); }
  catch {
    // Grab first {...} block as fallback
    const m = text.match(/\{[\s\S]*\}/);
    if (!m) return null;
    try { parsed = JSON.parse(m[0]); } catch { return null; }
  }

  const allowed = new Set(allowedNeighborIds);
  const asStrArr = (v, cap) => Array.isArray(v)
    ? v.map((x) => String(x).trim()).filter(Boolean).slice(0, cap)
    : [];
  const asNeighborArr = (v, cap) => asStrArr(v, cap).filter((id) => allowed.has(id));

  return {
    summary:         String(parsed.summary || "").trim(),
    mitre:           asStrArr(parsed.mitre, 5).filter((x) => MITRE_RE.test(x)),
    apis:            asStrArr(parsed.apis, 10),
    iocs:            asStrArr(parsed.iocs, 8),
    tags:            asStrArr(parsed.tags, 8).map((x) => x.toLowerCase()),
    chains_with:     asNeighborArr(parsed.chains_with, 3),
    alternatives:    asNeighborArr(parsed.alternatives, 3),
    counters:        asNeighborArr(parsed.counters, 3),
    stealth:         RANGE(parsed.stealth),
    complexity:      RANGE(parsed.complexity),
    os_requirements: String(parsed.os_requirements || "").trim().slice(0, 120),
    confidence:      RANGE(parsed.confidence),
  };
}

// ── Load model ────────────────────────────────────────────────────────────────
console.log(`\nLoading ${MODEL_ID} (dtype=${MODEL_DTYPE}) from ${MODEL_CACHE}...`);
const { env, pipeline } = await import("@huggingface/transformers");
env.cacheDir         = MODEL_CACHE;
env.useFSCache       = true;
env.allowRemoteModels = true;

const generator = await pipeline("text-generation", MODEL_ID, {
  dtype: MODEL_DTYPE,
});
console.log("Model loaded.\n");

// ── Enrich loop ───────────────────────────────────────────────────────────────
fs.mkdirSync(OUT_DIR, { recursive: true });

let ok = 0, fail = 0;
const t0 = Date.now();

// Graceful shutdown: flush state on SIGTERM/SIGINT so partial progress is
// preserved when the CI runner cancels the job (timeout, cancel-in-progress).
let shuttingDown = false;
for (const sig of ["SIGTERM", "SIGINT"]) {
  process.on(sig, () => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n${sig} received — flushing state before exit`);
    try { writeJson(STATE_FILE, state); } catch { /* ignore */ }
    process.exit(130);
  });
}

for (let i = 0; i < candidates.length; i++) {
  const cand = candidates[i];
  const { entity, neighbors, hash } = cand;
  const label = `[${i + 1}/${candidates.length}] ${entity.id}`;
  process.stdout.write(`${label} ${truncate(entity.title, 60)} … `);

  const allowedNeighborIds = neighbors.map((n) => n.id);
  const messages = buildMessages(cand);

  try {
    const result = await generator(messages, {
      max_new_tokens:      MAX_NEW_TOKENS,
      do_sample:           false,     // deterministic
      temperature:         1.0,
      repetition_penalty:  1.1,
      chat_template_kwargs: { enable_thinking: false },
    });

    const generated = result?.[0]?.generated_text;
    const lastMsg   = Array.isArray(generated) ? generated.at(-1)?.content : String(generated ?? "");

    const parsed = parseModelOutput(lastMsg, entity, allowedNeighborIds);
    if (!parsed || !parsed.summary) {
      throw new Error("empty or unparseable model output");
    }

    const outRecord = {
      ...parsed,
      _model:  MODEL_ID,
      _dtype:  MODEL_DTYPE,
      _at:     new Date().toISOString(),
      _hash:   hash,
      _neighbors_used: neighbors,
    };

    writeJson(path.join(OUT_DIR, `${entity.id}.json`), outRecord);
    state.entities[entity.id] = hash;
    ok++;
    console.log(`✓ stealth=${parsed.stealth} cx=${parsed.complexity} conf=${parsed.confidence} chains=${parsed.chains_with.length} alts=${parsed.alternatives.length} counters=${parsed.counters.length}`);
  } catch (err) {
    fail++;
    console.log(`✗ ${err.message}`);
  }

  // Persist state periodically so re-runs after a crash are efficient
  if ((i + 1) % 25 === 0) writeJson(STATE_FILE, state);
}

writeJson(STATE_FILE, state);
try { await generator.dispose?.(); } catch { /* ignore */ }

const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
console.log(`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Enrichment complete in ${elapsed}s
   OK:     ${ok}
   Failed: ${fail}
   Out:    ${OUT_DIR}
   State:  ${STATE_FILE}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`);
