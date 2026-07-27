/**
 * apply-mapping.mjs
 *
 * Reads a JSONL + its sibling .mapping.json (produced by detect-format.mjs)
 * and emits data/normalized/<name>.jsonl in the canonical schema that
 * scripts/normalize-samples.mjs and scripts/ingest.mjs expect.
 *
 * The LLM output is treated as DATA — we only walk the JSONPath expressions
 * it produced, never execute anything.
 *
 * Usage:
 *   node scripts/apply-mapping.mjs data/incoming/foo.jsonl
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { sanitize } from "./lib/sanitize.mjs";

const input = process.argv[2];
if (!input) { console.error("Usage: node scripts/apply-mapping.mjs <input.jsonl>"); process.exit(1); }

const INPUT      = path.resolve(input);
const MAPPING    = INPUT.replace(/\.jsonl$/i, ".mapping.json");
const OUT_DIR    = path.resolve("data/normalized");
const QUARANTINE = path.resolve("data/incoming/quarantine");
const BASE       = path.basename(INPUT, path.extname(INPUT));

if (!fs.existsSync(INPUT))   { console.error(`Not found: ${INPUT}`);   process.exit(1); }
if (!fs.existsSync(MAPPING)) { console.error(`Not found: ${MAPPING} — run detect-format.mjs first`); process.exit(1); }

const spec = JSON.parse(fs.readFileSync(MAPPING, "utf8"));

// ── Guardrail: quarantine low-confidence detections ──────────────────────────
if (spec.confidence < 3) {
  fs.mkdirSync(QUARANTINE, { recursive: true });
  const qPath = path.join(QUARANTINE, path.basename(INPUT));
  const qMap  = qPath.replace(/\.jsonl$/i, ".mapping.json");
  fs.copyFileSync(INPUT,   qPath);
  fs.copyFileSync(MAPPING, qMap);
  console.log(`Quarantined (confidence ${spec.confidence}/5): ${qPath}`);
  console.log(`Human review required. Edit the mapping.json and move both files back to data/incoming/.`);
  process.exit(0);
}

// ── Minimal JSONPath evaluator ───────────────────────────────────────────────
// Supports: $ (root), .field, [N] (index), [*] (wildcard yields array)
function jsonpath(root, expr) {
  if (expr == null) return undefined;
  if (typeof expr !== "string") return undefined;
  if (!expr.startsWith("$")) return undefined;

  const tokens = [];
  let i = 1;
  while (i < expr.length) {
    const c = expr[i];
    if (c === ".") { i++; continue; }
    if (c === "[") {
      const end = expr.indexOf("]", i);
      if (end === -1) return undefined;
      const inner = expr.slice(i + 1, end).trim();
      tokens.push(inner === "*" ? { wildcard: true }
                : /^\d+$/.test(inner) ? { index: Number(inner) }
                : { key: inner.replace(/^["']|["']$/g, "") });
      i = end + 1;
      continue;
    }
    // read identifier
    let j = i;
    while (j < expr.length && !".[".includes(expr[j])) j++;
    tokens.push({ key: expr.slice(i, j) });
    i = j;
  }

  let ctx = [root];
  for (const t of tokens) {
    const next = [];
    for (const v of ctx) {
      if (v == null) continue;
      if (t.wildcard) {
        if (Array.isArray(v))       next.push(...v);
        else if (typeof v === "object") next.push(...Object.values(v));
      } else if (t.index != null) {
        if (Array.isArray(v)) next.push(v[t.index]);
      } else if (t.key != null) {
        next.push(v[t.key]);
      }
    }
    ctx = next;
  }
  // Collapse to scalar unless we saw a wildcard (arrays stay arrays)
  const hadWildcard = tokens.some((t) => t.wildcard);
  return hadWildcard ? ctx : ctx[0];
}

// ── Apply mapping ────────────────────────────────────────────────────────────
const src = fs.readFileSync(INPUT, "utf8");
const lines = src.split("\n").filter(Boolean);
console.log(`Applying mapping to ${lines.length} records from ${path.basename(INPUT)}`);

const fm    = spec.field_map || {};
const konst = spec.constants || {};

function findTextFallback(obj, keys, depth = 0) {
  if (depth > 6 || obj == null || typeof obj !== "object") return null;
  for (const k of keys) {
    if (typeof obj[k] === "string" && obj[k].trim().length > 0) return obj[k];
  }
  for (const [, v] of Object.entries(obj)) {
    if (typeof v === "object" && v !== null) {
      const res = findTextFallback(v, keys, depth + 1);
      if (res) return res;
    }
  }
  return null;
}

const out = [];
const failures = [];
const seenIds  = new Set();

for (let idx = 0; idx < lines.length; idx++) {
  let rec;
  try { rec = JSON.parse(lines[idx]); }
  catch { failures.push({ line: idx + 1, reason: "invalid JSON" }); continue; }

  const val = (jp) => jp ? jsonpath(rec, jp) : undefined;

  let promptRaw = val(fm.prompt);
  let answerRaw = val(fm.answer);

  if (answerRaw == null || String(answerRaw).trim() === "" || typeof answerRaw === "object") {
    answerRaw = findTextFallback(rec, ["assessment", "answer", "body", "solution", "response", "content", "summary", "text", "description"]);
  }
  if (promptRaw == null || String(promptRaw).trim() === "" || typeof promptRaw === "object") {
    promptRaw = findTextFallback(rec, ["prompt", "question", "scenario", "unit_id", "title", "input", "topic", "role"]);
  }

  const prompt = promptRaw == null ? "" : (typeof promptRaw === "object" ? JSON.stringify(promptRaw) : String(promptRaw)).trim();
  const answer = answerRaw == null ? "" : (typeof answerRaw === "object" ? JSON.stringify(answerRaw) : String(answerRaw)).trim();

  // Skip records with no answer content — unusable for the vault
  if (!answer) { failures.push({ line: idx + 1, reason: "empty answer" }); continue; }

  // ID resolution
  let id;
  if (spec.id_strategy === "field") {
    const idRaw = val(fm.id);
    id = idRaw == null ? null : String(idRaw).trim();
    if (!id) {
      // fall back to hash
      id = "h_" + crypto.createHash("sha256").update(prompt + "\n" + answer).digest("hex").slice(0, 16);
    }
  } else {
    id = "h_" + crypto.createHash("sha256").update(prompt + "\n" + answer).digest("hex").slice(0, 16);
  }

  if (seenIds.has(id)) { failures.push({ line: idx + 1, reason: `duplicate id ${id}` }); continue; }
  seenIds.add(id);

  const category = (val(fm.category) ?? konst.category ?? "unknown").toString();
  const source   = val(fm.source);
  let tags       = val(fm.tags);
  if (!Array.isArray(tags)) tags = tags == null ? [] : [String(tags)];
  tags = tags.map((t) => String(t).trim()).filter(Boolean).slice(0, 10);

  out.push(sanitize({
    id,
    prompt,
    answer,
    kind:         konst.kind ?? "tradecraft_qa",
    category:     String(category).toLowerCase().replace(/\s+/g, "_"),
    publishState: konst.publishState ?? "core",
    tags,
    source:       source ? String(source) : spec.source_name,
    _ingest: {
      from_file:    path.basename(INPUT),
      mapping_spec: spec.source_name,
      ingested_at:  new Date().toISOString(),
    },
  }));
}

// ── Fail-safe: too many failures = quarantine ────────────────────────────────
const failRatio = failures.length / lines.length;
if (failRatio > 0.20) {
  fs.mkdirSync(QUARANTINE, { recursive: true });
  const report = { source: path.basename(INPUT), total: lines.length, failed: failures.length, ratio: failRatio, failures: failures.slice(0, 50) };
  fs.writeFileSync(path.join(QUARANTINE, `${BASE}.report.json`), JSON.stringify(report, null, 2));
  console.error(`Fail ratio ${(failRatio * 100).toFixed(1)}% > 20% — quarantining. Report: ${path.join(QUARANTINE, `${BASE}.report.json`)}`);
  process.exit(2);
}

fs.mkdirSync(OUT_DIR, { recursive: true });
const outPath = path.join(OUT_DIR, `${BASE}.jsonl`);
fs.writeFileSync(outPath, out.map((r) => JSON.stringify(r)).join("\n") + "\n");

console.log(`\nNormalized ${out.length}/${lines.length} records`);
console.log(`  failures       : ${failures.length}`);
console.log(`  written        : ${outPath}`);
console.log(`  source_name    : ${spec.source_name}`);
console.log(`  confidence     : ${spec.confidence}/5`);
console.log(`  kind (const)   : ${konst.kind ?? "tradecraft_qa"}`);
if (failures.length) {
  const byReason = failures.reduce((a, f) => (a[f.reason] = (a[f.reason] || 0) + 1, a), {});
  console.log(`  failure reasons:`);
  for (const [r, n] of Object.entries(byReason)) console.log(`    ${n.toString().padStart(4)}  ${r}`);
}
