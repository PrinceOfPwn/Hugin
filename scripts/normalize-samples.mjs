#!/usr/bin/env node
/**
 * normalize-samples.mjs
 *
 * Reads all .jsonl files from hugin/samples_export/** and:
 *  1. Normalizes heterogeneous formats into a single canonical schema
 *  2. Anonymizes all private source identifiers (cert_origin, model names, slugs, etc.)
 *  3. Emits one unified hugin/samples_normalized.jsonl ready for enrich-qa.mjs + import-qa.mjs
 *
 * Supported input formats:
 *   A) v5 / augmented / legacy (flat records with task_type, input/scenario, answer, conversation)
 *   B) gateway / subagents (flat with scenario, answer, evidence, memory_writes, _adapter_target)
 *   C) rft (messages[] + meta{} format for benchmark traces)
 *   D) gateway verifier (prompt + answer with embedded JSON decision, task_type=verifier)
 *
 * Usage:
 *   node scripts/normalize-samples.mjs [--dry-run] [--limit=N]
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// ── Config ────────────────────────────────────────────────────────────────────
const SAMPLES_ROOT = path.resolve("hugin/samples_export");
const OUTPUT_FILE  = path.resolve("hugin/samples_normalized.jsonl");

const args   = process.argv.slice(2);
const DRY_RUN = args.includes("--dry-run");
const LIMIT   = (() => {
  const l = args.find((a) => a.startsWith("--limit="));
  return l ? Number.parseInt(l.split("=")[1], 10) : Infinity;
})();

const sha256   = (v) => crypto.createHash("sha256").update(String(v)).digest("hex");
const shortId  = (v) => sha256(v).slice(0, 16);

// ── Anonimization Rules ───────────────────────────────────────────────────────
// Maps raw strings → public-safe labels used throughout the text and metadata
const CERT_MAP = {
  // Cert origins → generic source labels
  "osed":          "Source A",
  "osep":          "Source A",
  "oscp":          "Source A",
  "oswa":          "Source A",
  "ose":           "Source A",
  "oswp":          "Source A",
  "pen-200":       "Source A",
  "pen200":        "Source A",
  "exp-312":       "Source A",
  "web-200":       "Source A",
  "web200":        "Source A",
  "exp-301":       "Source A",
  "sans-sec670":   "Source B",
  "sans-sec760":   "Source B",
  "sans-sec560":   "Source B",
  "sec670":        "Source B",
  "sec760":        "Source B",
  "sec560":        "Source B",
  "crto":          "Source B",
  "crte":          "Source B",
  "maldev":        "Source B",
  "maldev-academy":"Source B",
};

const MODEL_MAP = {
  // Model names → generic identifiers
  "alibaba/qwen3.6-plus":         "model-a",
  "grok-4.3":                     "model-b",
  "mimo-v2.5-pro":                "model-c",
  "claude-sonnet-4-6":            "model-d",
  "claude-sonnet-4-5":            "model-d",
  "qwen3.6:27b-q4_k_m":          "model-e",
  "external-premium-curator":     "model-f",
  "gemini-3.5-flash":             "model-g",
  "gemini-3.6-flash":             "model-g",
  "deepseek-v4-pro":              "model-h",
  "deepseek-v3":                  "model-h",
};

function anonModel(raw) {
  if (!raw) return null;
  const key = String(raw).toLowerCase().trim();
  return MODEL_MAP[key] ?? (key.includes("qwen") ? "model-e" : key.includes("gemini") ? "model-g" : key.includes("claude") ? "model-d" : "model-x");
}

function anonCert(raw) {
  if (!raw) return null;
  const key = String(raw).toLowerCase().trim();
  return CERT_MAP[key] ?? null;
}

// Strip private identifiers from free-text strings
const TEXT_RULES = [
  // Private URLs — first, before any text replacements
  [/https?:\/\/[^\s)\]}"']*(?:offsec\.com|offensive-security\.com|maldevacademy\.com|sans\.org|linktr\.ee|offsecexam)[^\s)\]}"']*/gi, "[private-url]"],
  // AWS Credentials — redact before any other processing
  [/\bAKI[A-Z0-9]{16,}\b/g, "[aws-key-id]"],
  [/(?<=[Aa][Ww][Ss]_?[Ss][Ee][Cc][Rr][Ee][Tt][\s=:'"]*)[A-Za-z0-9/+]{40}\b/g, "[aws-secret]"],
  // Generic high-entropy secret patterns (40-char base64 sequences next to known secret field names)
  [/(?<=(?:SECRET|secret|key|KEY|token|TOKEN|password|PASSWORD)["':\s_-]{0,5})[A-Za-z0-9/+=]{32,50}(?=[^A-Za-z0-9/+=]|$)/gm, "[redacted-secret]"],
  // Specific cert/course names → Source A
  [/\b(?:OSED|OSEP|OSCP|OSWA|OSWP|PEN-200|PEN200|EXP-312|WEB-200|WEB200|EXP-301)\b/gi, "Source A"],
  // Specific cert/course names → Source B
  [/\bSANS[- ]?SEC\d{3}(?:\.\d+)?\b/gi, "Source B"],
  [/\bSEC\d{3}(?:\.\d+)?\b/gi, "Source B"],
  [/\bSANS(?:\s+Institute)?\b/gi, "Source B"],
  [/\bCRTO\d?\b/gi, "Source B"],
  [/\bCRTE\b/gi, "Source B"],
  [/\bMalDev(?:[_ -]*(?:Academy|Malware))?\b/gi, "Source B"],
  // Domain patterns without https:// prefix
  [/(?<![a-zA-Z0-9])offensive-security\.com/gi, "[private-domain]"],
  [/\bCertified\s+Red\s+Team(?:\s+Operator)?\b/gi, "Source B"],
  // OffSec / Offensive Security as organization name
  [/\bOffensive\s+Security\b/gi, "Source C"],
  [/\bOffSec\b/gi, "Source C"],
  // Local filesystem paths
  [/\/(?:Users|home)\/[^\s/]+\/[^\s)\]}"']+/g, "[private-path]"],
  [/[A-Za-z]:(?:\\+|\/+)(?:Users|home)(?:\\+|\/+)[^\s)\]}"']+/g, "[private-path]"],
  // Usernames
  [/\b(?:emiperalta|tamarisk)\b/gi, "operator"],
  // Source field markers
  [/\bOWN_NOTES\b/gi, "curated-notes"],
  [/\bauthorized-lab\b/gi, "authorized-environment"],
  [/\boffsecexam\b/gi, "[private-source]"],
];

function sanitizeText(value) {
  if (typeof value !== "string") return value;
  let s = value;
  for (const [pattern, replacement] of TEXT_RULES) {
    s = s.replace(pattern, replacement);
  }
  // Collapse double spaces
  return s.replace(/[ \t]{2,}/g, " ").replace(/ +([,.;:])/g, "$1").trim();
}

function sanitizeDeep(value) {
  if (typeof value === "string") return sanitizeText(value);
  if (Array.isArray(value)) return value.map(sanitizeDeep);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, sanitizeDeep(v)]));
  }
  return value;
}

// ── Task type normalization ───────────────────────────────────────────────────
function normalizeTask(raw) {
  const map = {
    exploit_dev:       "exploit_dev",
    exploitdev:        "exploit_dev",
    exploit_development: "exploit_dev",
    web_exploit:       "web_exploit",
    web_exploitation:  "web_exploit",
    post_exploit:      "post_exploitation",
    post_exploitation: "post_exploitation",
    ad_attack:         "lateral_movement",
    ad_lateral:        "lateral_movement",
    lab_solve:         "lab_methodology",
    verifier:          "verifier_qa",
    evasion:           "evasion",
    reversing:         "reversing",
    malware_analysis:  "malware_analysis",
    shellcode:         "exploit_dev",
    rop:               "exploit_dev",
    exploit_chain:     "exploit_dev",
  };
  if (!raw) return "research";
  const key = String(raw).toLowerCase().replace(/[-\s]+/g, "_");
  return map[key] ?? key;
}

// ── Format detectors & normalizers ────────────────────────────────────────────

/**
 * Format C: RFT benchmark trace  → { messages[], meta{} }
 */
function normalizeRFT(rec) {
  const meta   = rec.meta ?? {};
  const msgs   = rec.messages ?? [];
  const user   = msgs.find((m) => m.role === "user");
  const asst   = msgs.find((m) => m.role === "assistant");

  const prompt = sanitizeText(user?.content ?? "");
  const answer = sanitizeText(asst?.content ?? "");

  return {
    format: "rft",
    task: normalizeTask(meta.task_type ?? meta.skill_axis ?? "exploit_dev"),
    prompt,
    answer,
    conversation: null,
    near_miss: [],
    tags: [meta.skill_axis, meta.failure_axis].filter(Boolean).map(sanitizeText),
    difficulty: meta.difficulty ?? null,
    reasoning_trace: null,
    evidence: null,
    decision_axis: meta.skill_axis ?? null,
    source: "curated-notes",
    cert_origin: null,
  };
}

/**
 * Format D: gateway verifier (prompt text + JSON answer)
 */
function normalizeVerifier(rec) {
  // The prompt field contains the raw scenario; answer is JSON
  let answerText = "";
  try {
    const parsed = typeof rec.answer === "string" ? JSON.parse(rec.answer) : rec.answer;
    answerText = [
      parsed.decision ? `**Verdict:** ${parsed.decision}` : "",
      parsed.reasoning ? `**Reasoning:** ${parsed.reasoning}` : "",
      parsed.near_miss_avoided ? `**Near-miss avoided:** ${parsed.near_miss_avoided}` : "",
    ].filter(Boolean).join("\n\n");
  } catch {
    answerText = rec.answer ?? "";
  }

  // Strip the "Contexto autorizado: verifier off-x." header from prompts
  const rawPrompt = String(rec.prompt ?? "").replace(/^Contexto autorizado:[^\n]*\n\n/i, "").replace(/\n\nTarea:[^\n]*/i, "");

  return {
    format: "verifier",
    task: "verifier_qa",
    prompt: sanitizeText(rawPrompt),
    answer: sanitizeText(answerText),
    conversation: null,
    near_miss: [],
    tags: (rec.tags ?? []).map(sanitizeText),
    difficulty: null,
    reasoning_trace: null,
    evidence: null,
    decision_axis: null,
    source: "curated-notes",
    cert_origin: null,
  };
}

/**
 * Formats A & B: standard v5/augmented/gateway/subagent records
 */
function normalizeStandard(rec) {
  const task = normalizeTask(rec.task_type ?? rec._adapter_target ?? rec.task ?? "research");

  // Primary text fields
  const prompt = sanitizeText(rec.input ?? rec.scenario ?? "");
  const answer = sanitizeText(rec.answer ?? "");

  // Multi-turn conversation (if present)
  let conversation = null;
  const rawConv = rec.conversation ?? rec.turns ?? null;
  if (Array.isArray(rawConv) && rawConv.length > 0) {
    conversation = rawConv.map((turn) => ({
      role: turn.role === "operator" ? "user" : (turn.role ?? "user"),
      content: sanitizeText(turn.content ?? ""),
    }));
  }

  // near_miss → normalize to simple string array
  const near_miss = (rec.near_miss ?? [])
    .map((nm) => {
      if (typeof nm === "string") return sanitizeText(nm);
      const val = nm.rejected_answer ?? nm.value ?? "";
      const why = nm.failure_mode ?? "";
      return sanitizeText(why ? `${val} — Failure: ${why}` : val);
    })
    .filter(Boolean);

  // Reasoning trace → clean array of {label, text}
  const reasoning_trace = (rec.reasoning_trace ?? rec.latent_supervision ?? [])
    .map((r) => ({ label: r.label ?? "", text: sanitizeText(r.text ?? "") }))
    .filter((r) => r.text);

  // Evidence → clean array of {id, quote} — replace source-specific IDs with sequential E1/E2...
  const evidence = (rec.evidence ?? [])
    .map((e, i) => ({ id: `E${i + 1}`, quote: sanitizeText(e.quote ?? "") }))
    .filter((e) => e.quote);

  // Tags
  const tags = [
    ...(rec.tags ?? []),
    ...(rec._primary_topic ? [rec._primary_topic] : []),
  ].map(sanitizeText).filter(Boolean);

  return {
    format: "standard",
    task,
    prompt,
    answer,
    conversation,
    near_miss,
    tags,
    difficulty: rec.difficulty ?? null,
    reasoning_trace: reasoning_trace.length > 0 ? reasoning_trace : null,
    evidence: evidence.length > 0 ? evidence : null,
    decision_axis: sanitizeText(rec.decision_axis ?? ""),
    source: "curated-notes",
    cert_origin: anonCert(rec.cert_origin),
  };
}

/**
 * Route a raw record to the appropriate normalizer.
 */
function normalize(rec) {
  // Format C: RFT benchmark trace
  if (rec.messages && Array.isArray(rec.messages) && rec.meta) {
    return normalizeRFT(rec);
  }
  // Format D: verifier (has prompt + JSON answer + task_type=verifier OR no task_type + has prompt field only)
  if (rec.task_type === "verifier" || (rec.prompt && !rec.input && !rec.scenario && !rec.task_type && !rec.messages)) {
    return normalizeVerifier(rec);
  }
  // Formats A/B: standard
  return normalizeStandard(rec);
}

// ── Collect all JSONL files ───────────────────────────────────────────────────
function collectJsonlFiles(dir) {
  const result = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) result.push(...collectJsonlFiles(full));
    else if (entry.name.endsWith(".jsonl")) result.push(full);
  }
  return result;
}

const allFiles = collectJsonlFiles(SAMPLES_ROOT);
console.log(`Found ${allFiles.length} JSONL files in ${SAMPLES_ROOT}:`);
for (const f of allFiles) console.log(`  ${path.relative(process.cwd(), f)}`);

// ── Process & emit ────────────────────────────────────────────────────────────
const out = DRY_RUN ? null : fs.createWriteStream(OUTPUT_FILE, { flags: "w" });

let total = 0;
let emitted = 0;
let skipped = 0;
const seenContentHashes = new Set();

const SKIP_TASK_TYPES = new Set(["verifier_qa"]); // Skip verifier records — they're meta, not knowledge

for (const file of allFiles) {
  const relPath = path.relative(process.cwd(), file);
  const lines = fs.readFileSync(file, "utf8").split("\n").filter(Boolean);
  let fileCount = 0;

  for (const line of lines) {
    if (emitted >= LIMIT) break;
    total++;

    let raw;
    try { raw = JSON.parse(line); }
    catch { skipped++; continue; }

    let normalized;
    try { normalized = normalize(raw); }
    catch (err) { console.warn(`  Normalize error in ${relPath}: ${err.message}`); skipped++; continue; }

    // Skip verifier-type records (they judge answers, they're not knowledge records)
    if (SKIP_TASK_TYPES.has(normalized.task)) { skipped++; continue; }

    // Skip records with no meaningful prompt or answer
    if (!normalized.prompt && !normalized.answer && !normalized.conversation) { skipped++; continue; }

    // Content-based deduplication
    const contentKey = shortId(`${normalized.task}:${normalized.prompt}:${normalized.answer}`);
    if (seenContentHashes.has(contentKey)) { skipped++; continue; }
    seenContentHashes.add(contentKey);

    // Generate stable ID
    const stableId = `qs:${shortId(`${relPath}:${total}`)}`;

    const output = {
      id: stableId,
      format: normalized.format,
      task: normalized.task,
      prompt: normalized.prompt,
      answer: normalized.answer,
      conversation: normalized.conversation ?? undefined,
      near_miss: normalized.near_miss?.length > 0 ? normalized.near_miss : undefined,
      tags: normalized.tags?.length > 0 ? normalized.tags : undefined,
      difficulty: normalized.difficulty ?? undefined,
      reasoning_trace: normalized.reasoning_trace ?? undefined,
      evidence: normalized.evidence ?? undefined,
      decision_axis: normalized.decision_axis || undefined,
      cert_origin: normalized.cert_origin ?? undefined,
      source: normalized.source,
      // Strip all private fields — no _model, _slug, _section_id, _source_file, etc.
    };

    if (DRY_RUN) {
      if (fileCount < 2) {
        console.log("\n--- Sample output ---");
        console.log(JSON.stringify(output, null, 2));
      }
    } else {
      out.write(JSON.stringify(output) + "\n");
    }

    emitted++;
    fileCount++;
  }

  console.log(`  ${relPath}: ${fileCount} records emitted`);
}

if (!DRY_RUN) out.end();

console.log(`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Normalization complete
 Total lines read  : ${total}
 Emitted           : ${emitted}
 Skipped           : ${skipped}
 Unique content    : ${seenContentHashes.size}
 Output            : ${DRY_RUN ? "(dry-run, none)" : OUTPUT_FILE}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`);

if (!DRY_RUN) {
  console.log("Next steps:");
  console.log("  node scripts/enrich-qa.mjs hugin/samples_normalized.jsonl hugin/samples_enriched.jsonl");
  console.log("  node scripts/import-qa.mjs hugin/samples_enriched.jsonl");
  console.log("  npm run data:build && npm run data:validate");
}
